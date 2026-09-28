//! Built-in scalar defaults for every step tunable, ported verbatim from
//! `vvaharness/config/__init__.py`'s `_STEP_DEFAULTS`. Deep-merged UNDER
//! any loaded config (see `load`) so a partial/hand-written config can
//! never leave a stage crate missing a knob it reads directly. Structural
//! keys (lists/dicts like `exclude_dirs`, `specialists`, `config_dedup`,
//! `allowed_tools`) are intentionally omitted here, same as the Python
//! original — the stages that read them already default those
//! internally, and a defaults-layer entry would interfere with the
//! append/replace merge semantics `append_merge` gives those fields.
//!
//! **A handful of values here deliberately differ from the SAME stage
//! crate's own `Step*Config::new()`** — `step6_verify.min_confidence`
//! (`7` here vs. `6` in `bc_stage_s6::Step6Config::new()`) and
//! `step4.neighbor_context_lines`/`neighbor_context_max` (`25`/`50` here
//! vs. `20`/`40` in `bc_stage_s4::Step4Config::new()`). This is not
//! drift to reconcile — the two sides are faithful ports of two
//! DIFFERENT Python values that happen to share the word "default":
//! this file ports `_STEP_DEFAULTS`, the deep-merge base every real
//! Python profile YAML (`sdk.yaml`/`full.yaml`/`taint.yaml`/
//! `default.yaml`) is merged onto; `Step*Config::new()` ports
//! `config/profiles/default.yaml` specifically — the profile
//! `orchestrator/config_paths.py::_default_config` actually loads when
//! no `--config` is passed, since this port has no embedded profile-file
//! system of its own to reproduce that indirection. `default.yaml`
//! explicitly overrides these three keys down from `_STEP_DEFAULTS`'
//! shipped values; `sdk.yaml`/`full.yaml`/`taint.yaml` do not, so they
//! see `_STEP_DEFAULTS`' values verbatim. Forcing both Rust sides to the
//! same number would silently break parity with one Python profile or
//! the other — verified directly against the real Python source, not
//! assumed from either side's own doc comment.

use serde_json::{json, Value};

pub fn step_defaults() -> Value {
    json!({
        // Python's `_STEP_DEFAULTS["step0"]` — this port previously had
        // no `step0` entry at all, on the (incorrect) premise that S0 has
        // no Python config namespace. `languages: null` means "no
        // filter", which is what `Step0Config::new()`'s empty vec already
        // encodes, so the key is carried for schema completeness rather
        // than to change anything.
        "step0": {
            // Python ships this `false` (its seed plane was experimental);
            // the Rust plane is deterministic, LLM-free in `rules` mode and
            // is what feeds framework routes, auth guards and seed taint
            // paths to every later stage. Off, the 2026-09-07 polyglot
            // runs carried none of it — `true` is the default here.
            "enabled": true,
            "callgraph_detection": "rules",
            "sources_yaml": null,
            "sinks_yaml": null,
            "languages": null,
        },
        "step1": {
            "max_turns": 40,
            "max_file_kb": 1024,
            // `mode`/`call_graph` are the two string keys `_STEP_DEFAULTS`
            // ships and this port never read. `call_graph` stays at
            // Python's own `"regex"` here — `bc_stage_s1::Step1Config::
            // new()` deliberately defaults to the tree-sitter backend
            // instead (better evidenced), and this layer's job is to
            // report what Python ships, not to reconcile the two.
            "mode": "full",
            "call_graph": "regex",
            "call_graph_validate": true,
            "call_graph_supplement": true,
            "call_graph_rounds": 4,
            "call_graph_max_targets": 3,
            "auto_exclude": false,
            "auto_exclude_max_tokens": 8000,
        },
        "step2": {
            "enabled": true,
            "max_tokens": 64000,
            "max_threats": 50,
            "baseline": "auto",
            "max_doc_chars": 20000,
            "max_manifest_chars": 4000,
            // `max_modules`/`max_entry_points` are the AST-FRONTIER caps
            // (`_gather_evidence`'s `ast_context_view(...)` arguments);
            // `max_prompt_*` are the prompt-display caps. The names
            // suggest the opposite and `default.yaml`'s own comment says
            // the opposite; the call site at `s2_threatmodel.py:229-251`
            // is authoritative.
            "max_modules": 100,
            "max_entry_points": 400,
            "max_graph_files": 220,
            "max_graph_sinks": 80,
            "max_graph_edges": 100,
            "max_notes_chars": 2500,
            "max_prompt_modules": 100,
            "max_prompt_entry_points": 400,
            "max_config_reps": 80,
            "max_api_artefacts": 100,
            "max_function_sites": 80,
            // Ported from v1.4.0 `_STEP_DEFAULTS["step2"]`: redacted
            // config-rep bodies, the bounded manifest walk, the asset and
            // boundary caps, and the (off by default) read-only agentic
            // threat model.
            "max_config_rep_chars": 2000,
            "max_config_rep_bodies": 12,
            "max_manifest_depth": 3,
            "max_manifests": 12,
            "max_manifests_per_kind": 2,
            "max_manifest_total_chars": 24000,
            "max_assets": 40,
            "max_trust_boundaries": 60,
            "agentic": false,
            "allowed_tools": ["Read", "Glob", "Grep"],
            "max_turns": 12,
        },
        "step3": {
            "max_tokens": 64000,
            "timeout": 3600,
            "taint_chunks": true,
            "taint_max_hops": 10,
            "taint_max_chunks": 60,
            "taint_files_per_hop": 5,
            "pack_by": "loc",
            // Ported from `_STEP_DEFAULTS`' own `true`, which no shipped
            // Python profile overrides — so unlike the three keys called
            // out in this module's doc comment, this one is NOT allowed to
            // diverge from `bc_stage_s3::Step3Config::new()`. A scan run
            // with `--config` and one run without must pack identically;
            // `bc-stage-s3`'s
            // `step_defaults_agree_with_step3_config_new_on_pack_merge_underfilled`
            // pins the two together.
            "pack_merge_underfilled": true,
            "chunk_token_budget": 180000,
            "chunk_overhead_tokens": 80000,
            "risk_chunk_loc": 10000,
            "catchall_enabled": true,
            "catchall_mode": "all",
            "catchall_chunk_loc": 4000,
            "catchall_max_files": 100,
            "max_files_per_chunk": 80,
            "specialist_chunk_loc": 10000,
            // ── C2 coverage/decomposition keys (upstream v1.3/v1.4) ──
            // `catchall_mode` above stays "all": upstream's default.yaml
            // ships "reachable_only" with a 0.5 ratio, but `_STEP_DEFAULTS`
            // registers "all" and this port deliberately keeps the wider
            // sweep (see `bc_stage_s3::Step3Config::catchall_mode`).
            "catchall_deduct_lens_coverage": false,
            "max_cohesion_groups": 64,
            "max_threat_fallback_chunks": 50,
            "threat_surface_fallbacks": true,
            "threat_fallback_max_files": 12,
            "max_prompt_threats": 50,
            "max_prompt_assets": 20,
            "max_prompt_boundaries": 30,
            "max_prompt_threat_context_chars": 2500,
            // The shipped home of S4's chunk-slicing mode: declared in
            // `step3` (only `profiles/taint.yaml` raises it to
            // "function"), read by S4's `_slice_mode`
            // (`s4_deepdive.py:993-1007`). S3 itself never looks at it.
            "taint_chunk_slice": "file",
        },
        "step4": {
            "parallel": 5,
            "timeout": 1800,
            "runs": 1,
            "vote_threshold": 1,
            "specialist_runs": 1,
            "line_bucket": 10,
            "max_findings_per_run": 10,
            "max_tokens": 64000,
            "neighbor_context_lines": 25,
            "neighbor_context_max": 50,
            // `null` (not "file") verbatim from `_STEP_DEFAULTS`: an
            // absent `step4` override means "read `step3`", which is what
            // `_slice_mode` does and what
            // `config_overrides::step4_taint_chunk_slice` reproduces. No
            // shipped Python profile sets this half.
            "taint_chunk_slice": null,
            "frontier_max_funcs_per_file": 24,
            // Upstream v1.4.0 gates shard siblings unconditionally on a
            // route with a prefix cache; this port cannot see the route
            // from S4, so it is an operator switch (see
            // `bc_stage_s4::Step4Config::shard_cache_gating`).
            "shard_cache_gating": true,
        },
        "step5_prefilter": {
            "min_pre_confidence": 0.6,
            "require_evidence": true,
            "ast_backfill_evidence": true,
        },
        "step6_verify": {
            "parallel": 5,
            "min_confidence": 7,
            "max_turns": 30,
            // Python's shipped profiles set it `false` explicitly; must
            // agree with `bc_stage_s6::Step6Config::new()`.
            "progress_file": false,
        },
        "step7_dedup": {
            "line_tolerance": 3,
            "semantic": true,
            "max_tokens": 64000,
            // No `_STEP_DEFAULTS` counterpart — the same-code-range /
            // different-CWE merge is a Rust-side addition (Python treats
            // a CWE mismatch as an outright veto and so never merges
            // across lenses at all). Must agree with
            // `bc_stage_s7::Step7Config::new()`.
            "merge_same_range_cwes": true,
            // Same story: the same-sink tier is a Rust-side addition.
            "merge_same_sink": true,
        },
        "step8": {
            "max_tokens": 64000,
            "timeout": 3600,
        },
        // The seven `syntax_check`..`verify_timeout_secs` keys have no
        // `_STEP_DEFAULTS` counterpart — they configure S10's safety
        // gates, which are a Rust-side addition with no Python original
        // (see `bc_stage_s10`'s own crate doc comment). Unlike the three
        // documented divergences above, these MUST agree with
        // `bc_stage_s10::Step10Config::new()`, and
        // `step_defaults_agree_with_step10_config_new` (in `bc-stage-s10`,
        // which is where both sides are visible at once) pins them.
        "step_remediate": {
            "max_turns": 40,
            "top_n_findings": 20,
            "syntax_check": true,
            "keep_unverified": false,
            "max_diff_lines": 200,
            "max_files_touched": 1,
            "dry_run": false,
            // `null`, not an empty string: absent means "run nothing",
            // whereas `""` would be a command `sh -c` accepts and passes.
            "verify_command": null,
            "verify_timeout_secs": 600,
            // Not a gate: one extra agentic session when the agent
            // describes a fix the write journal says it never wrote.
            "retry_unapplied_fix": true,
        },
        // `output.emit_unreachable_appendix` is read by
        // `config_overrides::apply_overrides`; it had no defaults entry,
        // so it only appeared in the merged tree if a config set it.
        "output": {
            "emit_unreachable_appendix": false,
        },
        // Not a step: the text progress lines `bc-cli` prints to stderr
        // (`progress_lines.rs`), read by
        // `config_overrides::scan_progress_override`. Python's
        // `scan_progress` section, whose built-in scalar default is off
        // with `compact` lines when on.
        "scan_progress": {
            "enabled": false,
            "style": "compact",
        },
        // Not a step: transport settings every stage shares, read by
        // `bc-cli`'s `llm_settings` (and `config_overrides::
        // llm_stream_large_responses_override`). Net-new versus Python,
        // which spells the two cache keys at the top level
        // (`cache_markers: "on"`, `cache_min_block_tokens`) and has no
        // transport or lifetime key at all.
        "llm": {
            "stream_large_responses": false,
            // `auto`: the Responses API for known reasoning models, Chat
            // Completions for everything else (docs/llm-transport.md).
            "openai_api": "auto",
            "cache_markers": true,
            "cache_min_block_tokens": null,
            "cache_ttl": "5m",
        },
        "step_validate": {
            "enabled": false,
            // S11's reasoning effort, Python's `DEFAULT_EFFORT`. Read by
            // `bc-cli`'s `config_overrides::apply_step11_overrides`;
            // `--reasoning-effort` and `models.validate.orchestrator.effort`
            // both override it.
            "effort": "high",
            "max_turns": 50,
            "max_findings": 20,
            // Net-new (Python flags every tie): score a one-step persona
            // tie as SPLIT rather than failing the fix closed.
            "split_ties_score": true,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_defaults_has_every_expected_top_level_step() {
        let d = step_defaults();
        for key in [
            "step0",
            "step1",
            "step2",
            "step3",
            "step4",
            "step5_prefilter",
            "step6_verify",
            "step7_dedup",
            "step8",
            "step_remediate",
            "step_validate",
            "output",
            "scan_progress",
            "llm",
        ] {
            assert!(d.get(key).is_some(), "missing step defaults for {key}");
        }
    }

    /// The nine `step2` narrowing caps, spelled the way Python's own
    /// `_STEP_DEFAULTS` spells them — `max_modules`/`max_entry_points`
    /// are the AST-frontier caps and `max_prompt_*` the display caps
    /// (`s2_threatmodel.py:229-251`), NOT the other way round.
    #[test]
    fn step2_carries_both_the_frontier_and_the_prompt_caps() {
        let d = step_defaults();
        assert_eq!(d["step2"]["max_modules"], 100);
        assert_eq!(d["step2"]["max_entry_points"], 400);
        assert_eq!(d["step2"]["max_graph_files"], 220);
        assert_eq!(d["step2"]["max_graph_sinks"], 80);
        assert_eq!(d["step2"]["max_graph_edges"], 100);
        assert_eq!(d["step2"]["max_notes_chars"], 2500);
        assert_eq!(d["step2"]["max_prompt_modules"], 100);
        assert_eq!(d["step2"]["max_prompt_entry_points"], 400);
    }

    /// The v1.4.0 `step2` keys, matching `Step2Config::new()`.
    #[test]
    fn step2_carries_the_v1_4_evidence_and_cap_keys() {
        let d = step_defaults();
        assert_eq!(d["step2"]["max_config_rep_chars"], 2000);
        assert_eq!(d["step2"]["max_config_rep_bodies"], 12);
        assert_eq!(d["step2"]["max_manifest_depth"], 3);
        assert_eq!(d["step2"]["max_manifests"], 12);
        assert_eq!(d["step2"]["max_manifests_per_kind"], 2);
        assert_eq!(d["step2"]["max_manifest_total_chars"], 24000);
        assert_eq!(d["step2"]["max_assets"], 40);
        assert_eq!(d["step2"]["max_trust_boundaries"], 60);
        assert_eq!(d["step2"]["agentic"], false);
        assert_eq!(
            d["step2"]["allowed_tools"],
            serde_json::json!(["Read", "Glob", "Grep"])
        );
        assert_eq!(d["step2"]["max_turns"], 12);
    }

    #[test]
    fn step0_and_step1_carry_pythons_string_mode_keys() {
        let d = step_defaults();
        assert_eq!(d["step0"]["callgraph_detection"], "rules");
        // Deliberately not Python's `false` — see the key's own comment.
        assert_eq!(d["step0"]["enabled"], true);
        assert_eq!(d["step1"]["mode"], "full");
        assert_eq!(d["step1"]["call_graph"], "regex");
        assert_eq!(d["step1"]["auto_exclude"], false);
        assert_eq!(d["step1"]["auto_exclude_max_tokens"], 8000);
        assert_eq!(d["step5_prefilter"]["ast_backfill_evidence"], true);
        assert_eq!(d["step3"]["catchall_mode"], "all");
        assert_eq!(d["output"]["emit_unreachable_appendix"], false);
        assert_eq!(d["scan_progress"]["enabled"], false);
        assert_eq!(d["scan_progress"]["style"], "compact");
    }

    #[test]
    fn step_defaults_spot_check_values() {
        let d = step_defaults();
        assert_eq!(d["step1"]["max_file_kb"], 1024);
        assert_eq!(d["step4"]["parallel"], 5);
        assert_eq!(d["step4"]["runs"], 1);
        assert_eq!(d["step7_dedup"]["line_tolerance"], 3);
        assert_eq!(d["step7_dedup"]["merge_same_range_cwes"], true);
        assert_eq!(d["step_validate"]["enabled"], false);
        assert_eq!(d["step_validate"]["split_ties_score"], true);
        assert_eq!(d["step_remediate"]["top_n_findings"], 20);
        assert_eq!(d["step_validate"]["effort"], "high");
    }

    /// The `llm` transport defaults: the library defaults
    /// (`bc_llm_client::CachePolicy::default()`) plus `auto` transport,
    /// so loading a config changes nothing a flag-only run would not do.
    #[test]
    fn llm_carries_the_transport_and_cache_defaults() {
        let d = step_defaults();
        assert_eq!(d["llm"]["stream_large_responses"], false);
        assert_eq!(d["llm"]["openai_api"], "auto");
        assert_eq!(d["llm"]["cache_markers"], true);
        assert_eq!(d["llm"]["cache_min_block_tokens"], Value::Null);
        assert_eq!(d["llm"]["cache_ttl"], "5m");
    }

    /// S4's chunk-slicing mode lives in TWO sections, exactly as Python
    /// ships it: declared under `step3` (`"file"`) with an optional
    /// `step4` override left `null`. Both halves have to be here — the
    /// `step3` value is what a config that mentions neither ends up
    /// using, and the explicit `step4` null is what makes
    /// `config_overrides::step4_taint_chunk_slice`'s fallback fire
    /// instead of the defaults layer pinning `step4` to a real string.
    #[test]
    fn taint_chunk_slice_is_declared_in_step3_and_left_null_in_step4() {
        let d = step_defaults();
        assert_eq!(d["step3"]["taint_chunk_slice"], "file");
        assert_eq!(d["step4"]["taint_chunk_slice"], Value::Null);
        assert_eq!(d["step4"]["frontier_max_funcs_per_file"], 24);
    }

    /// Must match `bc_stage_s4::Step4Config::new()`'s own `true`, so a
    /// config that sets nothing gates the same with or without `load()`.
    #[test]
    fn step4_gates_shard_siblings_by_default() {
        assert_eq!(step_defaults()["step4"]["shard_cache_gating"], true);
    }

    /// `stepN.timeout` is the per-call wall-clock deadline each stage
    /// crate now forwards onto `bc_llm_client::ChatRequest::timeout`
    /// (`Step3Config`/`Step4Config`/`Step8Config`'s own `timeout_secs`
    /// defaults). Those three `Step*Config::new()` values must equal the
    /// numbers here, or a config that sets nothing behaves differently
    /// depending on whether it went through `load()` — asserted from this
    /// side only, since `bc-config` sits below the stage crates and can't
    /// depend on them to read their constructors directly.
    ///
    /// Verified against the real Python source rather than assumed: these
    /// are `_STEP_DEFAULTS`' own values (`config/__init__.py:129,146,167`)
    /// and every shipped profile — `default.yaml`, `sdk.yaml`,
    /// `full.yaml`, `taint.yaml` — repeats exactly these three numbers, so
    /// there is no profile-override split here of the kind this module's
    /// doc comment describes for `min_confidence`/`neighbor_context_*`.
    #[test]
    fn step_timeouts_match_the_stage_crate_defaults_they_are_wired_to() {
        let d = step_defaults();
        assert_eq!(d["step3"]["timeout"], 3600);
        assert_eq!(d["step4"]["timeout"], 1800);
        assert_eq!(d["step8"]["timeout"], 3600);
    }

    /// The stages with no `timeout` key in Python's `_STEP_DEFAULTS` must
    /// not grow one here: their `Step*Config::new()` counterparts default
    /// `timeout_secs` to `None` (fall through to the shared gateway
    /// client's own timeout), and a defaults-layer entry would silently
    /// override that for every config that never mentions the key.
    #[test]
    fn steps_without_a_python_timeout_key_do_not_gain_one() {
        let d = step_defaults();
        for key in [
            "step0",
            "step1",
            "step2",
            "step5_prefilter",
            "step6_verify",
            "step7_dedup",
        ] {
            assert!(
                d[key].get("timeout").is_none(),
                "{key} must not define a timeout default"
            );
        }
    }

    /// Sampling knobs are per model ROLE in Python (`models.<role>.
    /// temperature`, read by `backends/llm.py::resolve`), never per step —
    /// so `_STEP_DEFAULTS` has no `temperature`/`seed` entry and neither
    /// does this port. Asserted so a later change wires them under
    /// `models.*` rather than quietly adding a second, conflicting home.
    #[test]
    fn no_step_defines_sampling_knobs() {
        let d = step_defaults();
        for (key, value) in d.as_object().expect("step_defaults is an object") {
            assert!(
                value.get("temperature").is_none() && value.get("seed").is_none(),
                "{key} must not define temperature/seed; those belong under models.<role>"
            );
        }
    }

    #[test]
    fn step_remediate_carries_every_safety_gate_default() {
        // The values themselves are pinned against
        // `bc_stage_s10::Step10Config::new()` by that crate's own
        // `step_defaults_agree_with_step10_config_new`; this only asserts
        // the keys are present at all, so a config that never mentions
        // them still resolves every knob a stage reads.
        let d = step_defaults();
        let section = &d["step_remediate"];
        for key in [
            "syntax_check",
            "keep_unverified",
            "max_diff_lines",
            "max_files_touched",
            "dry_run",
            "verify_command",
            "verify_timeout_secs",
        ] {
            assert!(
                section.get(key).is_some(),
                "missing step_remediate default for {key}"
            );
        }
        assert!(section["verify_command"].is_null());
    }

    #[test]
    fn step_defaults_is_a_fresh_value_each_call() {
        // Not a shared/mutable singleton -- callers can freely merge into
        // their own copy without affecting later calls.
        let mut a = step_defaults();
        a["step1"]["max_turns"] = Value::from(999);
        let b = step_defaults();
        assert_eq!(b["step1"]["max_turns"], 40);
    }
}
