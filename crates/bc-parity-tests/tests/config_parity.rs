//! Cross-checks `bc_config::merge::{deep_merge, replace_merge,
//! append_merge}` and `bc_config::env::expand` against the real
//! `vvaharness.config` module's underscore-prefixed helpers (the same
//! surface `vvaharness`'s own `tests/test_config.py` imports directly).

mod support;

use serde_json::{json, Value};
use std::collections::HashMap;

enum Case {
    Merge {
        op: &'static str,
        base: Value,
        over: Value,
    },
    Expand {
        value: Value,
        env: Vec<(&'static str, &'static str)>,
    },
}

fn oracle_entry(case: &Case) -> Value {
    match case {
        Case::Merge { op, base, over } => json!({"op": op, "base": base, "over": over}),
        Case::Expand { value, env } => {
            let env_obj: serde_json::Map<String, Value> = env
                .iter()
                .map(|(k, v)| ((*k).to_string(), Value::String((*v).to_string())))
                .collect();
            json!({"op": "expand", "value": value, "env": Value::Object(env_obj)})
        }
    }
}

fn rust_result(case: &Case) -> Value {
    match case {
        Case::Merge {
            op: "deep_merge",
            base,
            over,
        } => bc_config::deep_merge(base, over),
        Case::Merge {
            op: "replace_merge",
            base,
            over,
        } => bc_config::replace_merge(base, over),
        Case::Merge {
            op: "append_merge",
            base,
            over,
        } => bc_config::append_merge(base, over),
        Case::Merge { op, .. } => panic!("unknown op {op}"),
        Case::Expand { value, env } => {
            let map: HashMap<&str, &str> = env.iter().copied().collect();
            // No case interpolates a secret-named variable, so the
            // policy refusal (tested in bc-config itself) never fires.
            bc_config::expand(value, "", &|name| map.get(name).map(|s| s.to_string()))
                .expect("no secret-named variables in these cases")
        }
    }
}

#[test]
fn merge_and_expand_match_the_python_original() {
    let Some(py) = support::resolve() else {
        return;
    };

    let cases = vec![
        Case::Merge {
            op: "deep_merge",
            base: json!({"a": 1, "b": {"x": 1, "z": 9}}),
            over: json!({"b": {"x": 2, "y": 3}}),
        },
        Case::Merge {
            op: "deep_merge",
            base: json!({"a": {"x": 1}}),
            over: json!({"a": 5}),
        },
        Case::Merge {
            op: "deep_merge",
            base: json!({"a": [1, 2]}),
            over: json!({"a": [3]}),
        },
        Case::Merge {
            op: "replace_merge",
            base: json!({"a": {"x": 1}, "b": [1, 2]}),
            over: json!({"a": {"y": 2}, "b": [3]}),
        },
        Case::Merge {
            op: "append_merge",
            base: json!({"exclude_dirs": ["a", "b"], "config_dedup": {"exts": [".py"], "enabled": true}}),
            over: json!({"exclude_dirs": ["b", "c"], "config_dedup": {"exts": [".rs"]}}),
        },
        Case::Merge {
            op: "append_merge",
            base: json!({"a": 1}),
            over: json!({"a": [9]}),
        },
        Case::Merge {
            op: "append_merge",
            base: json!({"a": [1, 2]}),
            over: json!({"a": "x"}),
        },
        Case::Expand {
            value: json!("${FOO}"),
            env: vec![("FOO", "bar")],
        },
        Case::Expand {
            value: json!("${FOO:-fallback}"),
            env: vec![],
        },
        Case::Expand {
            value: json!("${FOO:-fallback}"),
            env: vec![("FOO", "")],
        },
        Case::Expand {
            value: json!("${FOO}"),
            env: vec![],
        },
        Case::Expand {
            value: json!({"sdk": {"api_key": "${KEY}", "verify_ssl": true}, "list": ["${KEY}", "plain", 42, null]}),
            env: vec![("KEY", "secret123")],
        },
        Case::Expand {
            value: json!(42),
            env: vec![],
        },
    ];

    let batch: Vec<Value> = cases.iter().map(oracle_entry).collect();
    let oracle_out = py.run_oracle("config_oracle.py", &Value::Array(batch));
    let oracle_out = oracle_out.as_array().expect("oracle returns a JSON array");
    assert_eq!(oracle_out.len(), cases.len());

    let mut mismatches = Vec::new();
    for (i, (case, py_result)) in cases.iter().zip(oracle_out).enumerate() {
        let rust = rust_result(case);
        if &rust != py_result {
            mismatches.push(format!("case {i}: rust={rust} python={py_result}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} cases mismatched:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
}
