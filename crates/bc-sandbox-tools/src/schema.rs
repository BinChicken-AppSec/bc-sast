//! Tool schemas, ported verbatim from `backends/localtools.py`'s
//! `_SCHEMAS` (the same source both `schemas_for`/`anthropic_schemas_for`
//! draw from in the Python original — here, [`bc_llm_client::ToolSpec`]
//! is already the shared, dialect-neutral shape both
//! `bc-llm-openai`/`bc-llm-anthropic` convert to their own envelope).

use bc_llm_client::ToolSpec;
use serde_json::json;

pub fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "Read".to_string(),
            description: "Read a file from the repository. Returns numbered lines.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to the repo root"},
                    "offset": {"type": "integer", "description": "0-based line to start from (default 0)"},
                    "limit": {"type": "integer", "description": "Max lines to return (default 2000)"},
                },
                "required": ["path"],
            }),
        },
        ToolSpec {
            name: "Glob".to_string(),
            description: "List files in the repository matching a glob pattern (e.g. **/*.java)."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {"pattern": {"type": "string"}},
                "required": ["pattern"],
            }),
        },
        ToolSpec {
            name: "Grep".to_string(),
            description: "Search file contents for a regex. Returns file:line:text for each match."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex"},
                    "path": {"type": "string", "description": "Restrict to this file or directory"},
                    "glob": {"type": "string", "description": "Restrict to files matching this glob"},
                    "ignore_case": {"type": "boolean"},
                    "context": {"type": "integer", "description": "Lines of context around each match"},
                },
                "required": ["pattern"],
            }),
        },
    ]
}

/// `Edit`/`Write` schemas — only ever appended to [`tool_specs`]'s output
/// when a [`crate::SandboxTools`] is constructed via `new_with_write`
/// (Phase 2's S10 remediation stage). Kept in a separate function (rather
/// than folded into `tool_specs` with a parameter) so a reader can see at
/// a glance which tools are read-only vs. mutating.
pub fn write_tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "Write".to_string(),
            description: "Create or overwrite a file in the repository.".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to the repo root"},
                    "content": {"type": "string", "description": "Full file content to write"},
                },
                "required": ["path", "content"],
            }),
        },
        ToolSpec {
            name: "Edit".to_string(),
            description: "Replace a unique, exact string occurrence in an existing file."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to the repo root"},
                    "old_string": {"type": "string", "description": "Exact text to replace; must occur exactly once"},
                    "new_string": {"type": "string", "description": "Replacement text"},
                },
                "required": ["path", "old_string", "new_string"],
            }),
        },
    ]
}

/// Schemas for the five deterministic fact tools, ported from the `@tool`
/// signatures and docstrings in `validation/tools/deep_tools.py:43-95`
/// (LangChain derives each tool's JSON schema from the annotated Python
/// signature there, so the parameter names below are that contract).
/// Appended to an executor's specs only by [`crate::FactTools`], which
/// only `bc_stage_s11` constructs — see its doc comment.
///
/// `DiffImpactMap`/`TestInventory` take no arguments at all, so they carry
/// an empty `properties` object and no `required` key; the two dialects
/// both accept that as "call me with `{}`".
pub fn fact_tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "DiffTouched".to_string(),
            description: "Return whether a file is in the remediation diff and which lines it added. \
                Prefer this over reading or grepping the diff yourself: the answer is computed, not inferred."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Repo-relative path exactly as the diff spells it (no a/ or b/ prefix)"},
                },
                "required": ["file_path"],
            }),
        },
        ToolSpec {
            name: "ChangedLines".to_string(),
            // Python names these "added line ranges" while building them
            // as (start, count) pairs; spelled out here so a persona does
            // not read the second element as an end line and cite the
            // wrong code.
            description: "Return the line runs a file gained in the remediation diff, as \
                [start_line, line_count] pairs on the post-fix file."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Repo-relative path exactly as the diff spells it (no a/ or b/ prefix)"},
                },
                "required": ["file_path"],
            }),
        },
        ToolSpec {
            name: "DiffImpactMap".to_string(),
            description: "Return every file the remediation diff changed, and whether any of them \
                looks like a trust boundary (auth/session/crypto/config/...). Takes no arguments."
                .to_string(),
            parameters: json!({"type": "object", "properties": {}}),
        },
        ToolSpec {
            name: "PatternScan".to_string(),
            description: "Return bounded, secret-free match metadata and a scan summary for \
                a deterministic regex pattern set swept over the repository, skipping \
                vendor/test/binary files. Sets: \"secret_exposure\" (hardcoded credentials), \
                \"insecure_value\" (disabled TLS verification, debug/anonymous-auth flags). \
                Match records carry only file and line, never the matched text. The final \
                item is a summary reporting counts, limits, and whether results were \
                truncated."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern_set": {
                        "type": "string",
                        "enum": ["secret_exposure", "insecure_value"],
                    },
                },
                "required": ["pattern_set"],
            }),
        },
        ToolSpec {
            name: "TestInventory".to_string(),
            description: "Inventory the repository's test files and flag which of them contain \
                negative/adversarial test markers (pytest.raises, toThrow, malformed, exploit, ...). \
                Takes no arguments."
                .to_string(),
            parameters: json!({"type": "object", "properties": {}}),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fact_tool_specs_exposes_exactly_the_five_python_fact_tools() {
        let specs = fact_tool_specs();
        let names: Vec<&str> = specs.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "DiffTouched",
                "ChangedLines",
                "DiffImpactMap",
                "PatternScan",
                "TestInventory"
            ]
        );
    }

    #[test]
    fn fact_tool_spec_names_match_the_exported_name_list() {
        // `FACT_TOOL_NAMES` is what `bc_stage_s11` builds its
        // `allowed_tools` from; `run_agentic` errors outright if an
        // allowed name is not advertised, so the two must not drift.
        let names: Vec<String> = fact_tool_specs().into_iter().map(|t| t.name).collect();
        assert_eq!(names, crate::FACT_TOOL_NAMES.to_vec());
    }

    #[test]
    fn the_two_argument_taking_fact_tools_require_their_argument() {
        for spec in fact_tool_specs() {
            let required = spec.parameters.get("required");
            match spec.name.as_str() {
                "DiffTouched" | "ChangedLines" => {
                    assert_eq!(required.unwrap().as_array().unwrap().len(), 1)
                }
                "PatternScan" => assert_eq!(required.unwrap()[0], "pattern_set"),
                // No-argument tools carry an empty property bag instead.
                _ => {
                    assert!(required.is_none(), "{} should take no arguments", spec.name);
                    assert!(spec.parameters["properties"]
                        .as_object()
                        .unwrap()
                        .is_empty());
                }
            }
        }
    }

    #[test]
    fn exposes_exactly_read_glob_and_grep() {
        let specs = tool_specs();
        let names: Vec<&str> = specs.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["Read", "Glob", "Grep"]);
    }

    #[test]
    fn write_tool_specs_exposes_exactly_write_and_edit() {
        let specs = write_tool_specs();
        let names: Vec<&str> = specs.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["Write", "Edit"]);
    }

    #[test]
    fn every_write_spec_requires_at_least_one_field() {
        for spec in write_tool_specs() {
            let required = spec.parameters["required"].as_array().unwrap();
            assert!(!required.is_empty(), "{} has no required fields", spec.name);
        }
    }

    #[test]
    fn every_spec_requires_at_least_one_field() {
        for spec in tool_specs() {
            let required = spec.parameters["required"].as_array().unwrap();
            assert!(!required.is_empty(), "{} has no required fields", spec.name);
        }
    }
}
