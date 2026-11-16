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

fn prior_findings_block(digest: &appsec_model::ProviderDigest) -> String {
    if digest.is_empty() {
        return String::new();
    }
    let mut lines = vec![format!(
        "Other scanners have already reported {} finding(s) on this repository. They are\n\
         unverified, but the areas they name are worth mapping carefully:",
        digest.total
    )];
    for hotspot in &digest.hotspots {
        lines.push(format!(
            "  - {}/ — {} prior finding(s)",
            hotspot.path, hotspot.count
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

pub fn build_user_prompt(
    skip_dirs: &str,
    provider_digest: &appsec_model::ProviderDigest,
) -> String {
    let prior = prior_findings_block(provider_digest);
    format!(
        "Map this repository for security analysis.\n\
         \n\
         {prior}\
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
         Explore the codebase thoroughly, then output the JSON ContextPackage."
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
    fn the_prompt_no_longer_carries_a_hand_fed_cve_list() {
        let prompt = build_user_prompt("node_modules", &appsec_model::ProviderDigest::default());
        assert!(
            !prompt.contains("Known CVEs"),
            "the legacy injected-CVE block is gone: {prompt}"
        );
    }

    #[test]
    fn skip_dirs_are_interpolated() {
        let prompt = build_user_prompt(
            "node_modules, target",
            &appsec_model::ProviderDigest::default(),
        );
        assert!(prompt.contains("node_modules, target"));
    }

    #[test]
    fn user_prompt_ends_with_the_explore_instruction() {
        let prompt = build_user_prompt("x", &appsec_model::ProviderDigest::default());
        assert!(prompt
            .ends_with("Explore the codebase thoroughly, then output the JSON ContextPackage."));
    }
}

#[cfg(test)]
mod prior_findings_tests {
    use super::*;
    use appsec_model::{ProviderDigest, ProviderHotspot};

    fn digest() -> ProviderDigest {
        ProviderDigest {
            total: 4,
            hotspots: vec![
                ProviderHotspot {
                    path: "src".to_string(),
                    count: 3,
                },
                ProviderHotspot {
                    path: "lib".to_string(),
                    count: 1,
                },
            ],
            ..ProviderDigest::default()
        }
    }

    #[test]
    fn an_empty_digest_adds_nothing_to_the_prompt() {
        let plain = build_user_prompt("node_modules", &ProviderDigest::default());
        assert!(!plain.contains("Other scanners"), "{plain}");
        assert!(plain.starts_with("Map this repository for security analysis."));
    }

    #[test]
    fn the_mapper_is_told_where_other_scanners_already_reported() {
        let prompt = build_user_prompt("node_modules", &digest());
        assert!(prompt.contains("already reported 4 finding(s)"), "{prompt}");
        assert!(prompt.contains("src/ — 3 prior finding(s)"), "{prompt}");
        assert!(prompt.contains("lib/ — 1 prior finding(s)"), "{prompt}");
    }

    #[test]
    fn the_prior_findings_are_marked_unverified() {
        let prompt = build_user_prompt("x", &digest());
        assert!(
            prompt.contains("unverified"),
            "the mapper must not treat another tool's output as ground truth: {prompt}"
        );
    }

    #[test]
    fn the_out_of_scope_section_still_follows_the_prior_findings() {
        let prompt = build_user_prompt("node_modules", &digest());
        let prior = prompt.find("Other scanners").expect("prior block present");
        let scope = prompt.find("OUT OF SCOPE").expect("scope block present");
        assert!(prior < scope, "{prompt}");
    }
}
