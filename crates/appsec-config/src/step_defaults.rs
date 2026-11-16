use serde_json::{json, Value};

pub fn step_defaults() -> Value {
    json!({
        "step0": {
            "enabled": true,
            "callgraph_detection": "rules",
            "sources_yaml": null,
            "sinks_yaml": null,
            "languages": null,
        },
        "step1": {
            "max_turns": 40,
            "max_file_kb": 1024,
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
            "catchall_deduct_lens_coverage": false,
            "max_cohesion_groups": 64,
            "max_threat_fallback_chunks": 50,
            "threat_surface_fallbacks": true,
            "threat_fallback_max_files": 12,
            "max_prompt_threats": 50,
            "max_prompt_assets": 20,
            "max_prompt_boundaries": 30,
            "max_prompt_threat_context_chars": 2500,
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
            "taint_chunk_slice": null,
            "frontier_max_funcs_per_file": 24,
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
            "progress_file": false,
        },
        "step7_dedup": {
            "line_tolerance": 3,
            "semantic": true,
            "max_tokens": 64000,
            "merge_same_range_cwes": true,
            "merge_same_sink": true,
        },
        "step8": {
            "max_tokens": 64000,
            "timeout": 3600,
        },
        "step_remediate": {
            "max_turns": 40,
            "top_n_findings": 20,
            "syntax_check": true,
            "keep_unverified": false,
            "max_diff_lines": 200,
            "max_files_touched": 1,
            "dry_run": false,
            "verify_command": null,
            "verify_timeout_secs": 600,
            "retry_unapplied_fix": true,
        },
        "output": {
            "emit_unreachable_appendix": false,
        },
        "scan_progress": {
            "enabled": false,
            "style": "compact",
        },
        "llm": {
            "stream_large_responses": false,
            "openai_api": "auto",
            "cache_markers": true,
            "cache_min_block_tokens": null,
            "cache_ttl": "5m",
        },
        "step_validate": {
            "enabled": false,
            "effort": "high",
            "max_turns": 50,
            "max_findings": 20,
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

    #[test]
    fn llm_carries_the_transport_and_cache_defaults() {
        let d = step_defaults();
        assert_eq!(d["llm"]["stream_large_responses"], false);
        assert_eq!(d["llm"]["openai_api"], "auto");
        assert_eq!(d["llm"]["cache_markers"], true);
        assert_eq!(d["llm"]["cache_min_block_tokens"], Value::Null);
        assert_eq!(d["llm"]["cache_ttl"], "5m");
    }

    #[test]
    fn taint_chunk_slice_is_declared_in_step3_and_left_null_in_step4() {
        let d = step_defaults();
        assert_eq!(d["step3"]["taint_chunk_slice"], "file");
        assert_eq!(d["step4"]["taint_chunk_slice"], Value::Null);
        assert_eq!(d["step4"]["frontier_max_funcs_per_file"], 24);
    }

    #[test]
    fn step4_gates_shard_siblings_by_default() {
        assert_eq!(step_defaults()["step4"]["shard_cache_gating"], true);
    }

    #[test]
    fn step_timeouts_match_the_stage_crate_defaults_they_are_wired_to() {
        let d = step_defaults();
        assert_eq!(d["step3"]["timeout"], 3600);
        assert_eq!(d["step4"]["timeout"], 1800);
        assert_eq!(d["step8"]["timeout"], 3600);
    }

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
        let mut a = step_defaults();
        a["step1"]["max_turns"] = Value::from(999);
        let b = step_defaults();
        assert_eq!(b["step1"]["max_turns"], 40);
    }
}
