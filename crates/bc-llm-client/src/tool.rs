//! The `ToolExecutor` boundary, ported from `vvaharness/backends/localtools.py`:
//! a jailed, read-only, local tool runner that both `LlmClient` dialects
//! drive identically. Execution is sync (bounded, capped local filesystem
//! I/O, matching the Python original) — callers that need it off the async
//! task (e.g. `bc-llm-agentic`) wrap it in `spawn_blocking` themselves.

use serde_json::Value;

/// One tool's name/description/JSON-schema-parameters, dialect-neutral.
/// Each `LlmClient` dialect implementation converts this into its own wire
/// envelope (OpenAI's `{"type": "function", "function": {...}}`, Anthropic's
/// `{"name", "description", "input_schema"}`) — this crate defines only the
/// shared shape, not either envelope.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

/// Errors are never propagated from [`ToolExecutor::execute`] as a Rust
/// `Result` — a tool failure (bad path, invalid regex, missing file) is
/// data the model itself needs to see and react to, not a process fault.
/// Every implementation returns its error as an `"ERROR: ..."`-prefixed
/// string, mirroring `localtools.execute`'s `except Exception` catch-all.
pub trait ToolExecutor: Send + Sync {
    /// Every tool this executor can run, independent of what a particular
    /// role's `allowed_tools` config asks for.
    fn available_tools(&self) -> Vec<ToolSpec>;

    fn execute(&self, name: &str, args: &Value) -> String;
}

/// Split `allowed` into the subset this executor supports and the subset it
/// doesn't, ported from `localtools.supported()`. The caller decides whether
/// a non-empty `missing` list is fatal (the Python `oai`/`sdk` backends
/// raise `NotImplementedError` for missing tools like `Bash`/`Edit`).
pub fn supported(executor: &dyn ToolExecutor, allowed: &[String]) -> (Vec<String>, Vec<String>) {
    let names: std::collections::HashSet<String> = executor
        .available_tools()
        .into_iter()
        .map(|t| t.name)
        .collect();
    let mut ok = Vec::new();
    let mut missing = Vec::new();
    for name in allowed {
        if names.contains(name) {
            ok.push(name.clone());
        } else {
            missing.push(name.clone());
        }
    }
    (ok, missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeExecutor;

    impl ToolExecutor for FakeExecutor {
        fn available_tools(&self) -> Vec<ToolSpec> {
            vec![
                ToolSpec {
                    name: "Read".to_string(),
                    description: "read a file".to_string(),
                    parameters: serde_json::json!({"type": "object"}),
                },
                ToolSpec {
                    name: "Glob".to_string(),
                    description: "list files".to_string(),
                    parameters: serde_json::json!({"type": "object"}),
                },
            ]
        }

        fn execute(&self, name: &str, _args: &Value) -> String {
            match name {
                "Read" => "file contents".to_string(),
                _ => format!("ERROR: tool '{name}' is not available on this backend"),
            }
        }
    }

    #[test]
    fn tool_spec_fields_are_accessible_and_comparable() {
        let spec = ToolSpec {
            name: "Read".to_string(),
            description: "read a file".to_string(),
            parameters: serde_json::json!({"type": "object"}),
        };
        assert_eq!(spec.clone(), spec);
    }

    #[test]
    fn supported_splits_allowed_into_ok_and_missing() {
        let exec = FakeExecutor;
        let allowed = vec!["Read".to_string(), "Glob".to_string(), "Bash".to_string()];
        let (ok, missing) = supported(&exec, &allowed);
        assert_eq!(ok, vec!["Read".to_string(), "Glob".to_string()]);
        assert_eq!(missing, vec!["Bash".to_string()]);
    }

    #[test]
    fn supported_with_all_allowed_tools_available() {
        let exec = FakeExecutor;
        let allowed = vec!["Read".to_string()];
        let (ok, missing) = supported(&exec, &allowed);
        assert_eq!(ok, allowed);
        assert!(missing.is_empty());
    }

    #[test]
    fn supported_with_no_tools_available() {
        let exec = FakeExecutor;
        let allowed = vec!["Bash".to_string(), "Edit".to_string()];
        let (ok, missing) = supported(&exec, &allowed);
        assert!(ok.is_empty());
        assert_eq!(missing, allowed);
    }

    #[test]
    fn execute_returns_data_not_a_result() {
        let exec = FakeExecutor;
        assert_eq!(exec.execute("Read", &Value::Null), "file contents");
        assert!(exec.execute("Bash", &Value::Null).starts_with("ERROR:"));
    }
}
