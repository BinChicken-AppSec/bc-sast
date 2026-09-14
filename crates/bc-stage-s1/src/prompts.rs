// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! S1's system/user prompts, ported verbatim from
//! `s1_preprocess.py`'s module-level `SYSTEM` constant and `run()`'s
//! inline `user_prompt` f-string. Kept as byte-identical text (not
//! independently re-rendered per call site beyond the CVE/skip-dirs
//! interpolation) for the same prompt-caching reason as `bc-prompts`.

use bc_model::Cve;

pub const SYSTEM: &str = "\
You are a security-focused codebase mapper. Explore this repository
using your built-in tools (Read, Glob, Grep) to build a structural
understanding.

1. Start with Glob to see the file layout and identify the primary language.
2. Grep for unsafe sinks (strcat, strcpy, sprintf, memcpy, system, exec, eval,
   pickle.loads, yaml.load, deserialize, etc — adapt to the language).
3. Grep for entry points (main, HTTP handlers, RPC handlers, socket listeners,
   CLI parsers, deserializers).
4. Read key files to understand purpose (one-line summary per module).
5. Build a rough call graph for paths from entry points to unsafe sinks.

Be efficient — broad searches first, then targeted reads.

IMPORTANT: Your FINAL output must be ONLY a JSON object with this exact schema
(no prose before or after):
{
  \"language\": \"primary language\",
  \"modules\": [{\"name\":\"str\", \"files\":[\"path\"], \"loc\":1234, \"purpose\":\"one-line\"}],
  \"entry_points\": [{\"file\":\"str\", \"function\":\"str\", \"kind\":\"network|ipc|file|cli|deserialization|other\", \"reachable_from_unauth\":true}],
  \"unsafe_sinks\": [{\"file\":\"str\", \"line\":123, \"function\":\"str\", \"snippet\":\"the line\"}],
  \"call_graph\": {\"caller_func\": [\"callee_func\"]},
  \"notes\": \"free-form observations\"
}

Do NOT include raw source code in the output. Include file paths, line numbers,
function names, and short snippets (max 120 chars each) only.";

fn cve_block(known_cves: &[Cve]) -> String {
    if known_cves.is_empty() {
        return "  (none)".to_string();
    }
    known_cves
        .iter()
        .map(|c| format!("  - {}: {}", c.id, c.summary))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `skip_dirs` is the advisory dir-name list (Option B in the Python
/// source) — enforcement is [`crate::pure::scope_filter`], applied
/// deterministically afterward regardless of whether the agent honored
/// this hint.
pub fn build_user_prompt(known_cves: &[Cve], skip_dirs: &str) -> String {
    format!(
        "Map this repository for security analysis.\n\
         \n\
         Known CVEs already filed (do NOT re-flag these as new findings):\n\
         {}\n\
         \n\
         OUT OF SCOPE — do NOT Glob into, Grep through, or Read files under any\n\
         directory named one of these (tests / build artifacts / vendor / infra; they\n\
         are not production attack surface and waste your tool budget):\n\
         \u{20}\u{20}{skip_dirs}\n\
         \n\
         Also skip individual test files matching:\n\
         \u{20}\u{20}*_test.*  *.test.*  *.spec.*  *Test.java  *Tests.java  *IT.java  conftest.py\n\
         \n\
         Do not report unsafe_sinks, entry_points or modules from those paths.\n\
         \n\
         Explore the codebase thoroughly, then output the JSON ContextPackage.",
        cve_block(known_cves)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_prompt_mentions_the_expected_schema_keys() {
        for key in [
            "language",
            "modules",
            "entry_points",
            "unsafe_sinks",
            "call_graph",
            "notes",
        ] {
            assert!(SYSTEM.contains(key), "missing schema key: {key}");
        }
        assert!(SYSTEM.starts_with("You are a security-focused codebase mapper."));
    }

    #[test]
    fn cve_block_empty_list_is_none_placeholder() {
        let prompt = build_user_prompt(&[], "node_modules");
        assert!(prompt.contains("(none)"));
    }

    #[test]
    fn cve_block_lists_id_and_summary() {
        let cves = vec![Cve {
            id: "CVE-2024-1".to_string(),
            summary: "a bug".to_string(),
            affected_files: vec![],
            cvss: None,
            patched: false,
        }];
        let prompt = build_user_prompt(&cves, "node_modules");
        assert!(prompt.contains("CVE-2024-1: a bug"));
    }

    #[test]
    fn skip_dirs_are_interpolated() {
        let prompt = build_user_prompt(&[], "node_modules, target");
        assert!(prompt.contains("node_modules, target"));
    }

    #[test]
    fn user_prompt_ends_with_the_explore_instruction() {
        let prompt = build_user_prompt(&[], "x");
        assert!(prompt
            .ends_with("Explore the codebase thoroughly, then output the JSON ContextPackage."));
    }
}
