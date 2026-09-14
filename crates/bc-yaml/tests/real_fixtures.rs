//! Integration tests against real config/input YAML files copied verbatim
//! from the Python reference implementation (Apache-2.0, same project) —
//! not hand-crafted cases, to catch anything the unit tests' synthetic
//! examples might have missed.

fn parse_fixture(name: &str) -> serde_json::Value {
    let path = concat_fixture_path(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    bc_yaml::parse(&text).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

fn concat_fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn default_yaml_parses_and_has_expected_shape() {
    let v = parse_fixture("default.yaml");
    assert_eq!(v["models"]["deepdive"]["id"], "claude-sonnet-4-6");
    assert_eq!(v["models"]["deepdive"]["via"], "cli");
    assert_eq!(v["models"]["remediate"]["id"], "claude-opus-4-8");
    assert_eq!(v["sdk"]["api_key"], "${ANTHROPIC_SDK_API_KEY}");
    assert_eq!(v["sdk"]["verify_ssl"], true);
    assert_eq!(v["step1"]["auto_exclude"], true);
    assert_eq!(v["step1"]["max_budget_usd"], 25.0);
    assert_eq!(
        v["step1"]["allowed_tools"],
        serde_json::json!(["Read", "Glob", "Grep"])
    );
    assert!(v["step1"]["exclude_dirs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "node_modules"));
    assert_eq!(v["step1"]["config_dedup"]["enabled"], true);
    assert_eq!(v["step1"]["config_dedup"]["min_cluster_size"], 5);
    assert_eq!(
        v["step3"]["specialists"],
        serde_json::json!(["crypto", "logic-bug", "access-control", "batch-etl", "iac"])
    );
    assert_eq!(v["step4"]["parallel"], 5);
    assert_eq!(v["step7_dedup"]["line_tolerance"], 3);
    assert_eq!(v["step_remediate"]["enabled"], true);
    assert_eq!(v["step_remediate"]["top_n_findings"], 5);
    assert_eq!(v["step_validate"]["max_findings"], 20);
    assert_eq!(v["inject"]["cve_file"], "./inputs/known_cves.json");
    assert_eq!(
        v["output"]["preserve_on_cleanup"],
        serde_json::json!(["security-scan", "security-remediation"])
    );
    assert!(v["batch"]["skip_repo_patterns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "*automation*"));
}

#[test]
fn sdk_yaml_parses() {
    let v = parse_fixture("sdk.yaml");
    assert!(v["models"].is_object());
    assert!(v.get("models").is_some());
}

#[test]
fn full_yaml_parses() {
    let v = parse_fixture("full.yaml");
    assert!(v["models"].is_object());
}

#[test]
fn design_controls_example_parses_sequence_of_mappings() {
    let v = parse_fixture("design_controls.example.yaml");
    let controls = v["controls"].as_array().unwrap();
    assert_eq!(controls.len(), 2);
    assert_eq!(controls[0]["name"], "api-gateway-auth");
    assert_eq!(controls[0]["kind"], "auth");
    assert_eq!(
        controls[0]["protects"],
        serde_json::json!(["src/handlers/**"])
    );
    assert_eq!(controls[1]["name"], "seccomp-sandbox");
    assert_eq!(controls[1]["kind"], "sandbox");
}

#[test]
fn remediation_policy_example_parses_deny_allow_lists() {
    let v = parse_fixture("remediation_policy.yaml.example");
    assert_eq!(v["schema_version"], "1.0");
    assert_eq!(v["default_action"], "deny");
    assert!(v["kill_switch"]["env_var"].is_string());

    let deny = v["deny"].as_array().unwrap();
    assert_eq!(deny[0]["id"], "CWE-284");
    assert_eq!(
        deny[0]["reason"],
        "requires knowledge of intended authorization policy"
    );
    assert!(deny[0]["descendants"].as_array().unwrap().len() > 1);

    // `allow:` entries are written in this file as flow-style mappings on
    // the dash line (`- { id: CWE-89  }`) — a real regression case: this
    // used to silently misparse into a garbage key/value pair instead of
    // `{"id": "CWE-89"}`, and the shallow assertions above alone would
    // never have caught it.
    let allow = v["allow"].as_array().unwrap();
    assert!(allow.contains(&serde_json::json!({"id": "CWE-89"})));
    assert!(allow.contains(&serde_json::json!({"id": "CWE-78"})));
}

#[test]
fn remediation_playbook_parses_block_scalars() {
    let v = parse_fixture("remediation_playbook.yaml");
    assert_eq!(v["schema_version"], "1.0");
    assert_eq!(v["policy"]["max_diff_lines"], 40);
    assert_eq!(v["policy"]["max_files_touched"], 2);
    assert_eq!(v["policy"]["allow_new_dependencies"], false);
    let forbid: Vec<&str> = v["policy"]["forbid_patterns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    // Confirms the double-backslash regex-escape handling exercised in
    // scalar.rs's unit tests also round-trips through the full parser on
    // the real file, not just a synthetic snippet.
    assert!(forbid.iter().any(|p| p.contains(r"\s*")));
    assert!(v["policy"]["never_autofix_cwes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "CWE-284"));

    // Precise trailing-newline/folding correctness for the folded (`>`)
    // and literal (`|`) block scalars, not just substring containment —
    // this is exactly the shape the join-vs-per-line-newline bug (fixed
    // during this crate's development) would have gotten wrong.
    let default_py = &v["cwe"]["CWE-89"]["strategies"]["python"]["default"];
    assert_eq!(
        default_py["instruction"],
        "Replace string-formatted SQL with a parameterized query using \
the DB-API `execute(sql, params)` form. Do NOT use f-strings \
or % formatting in the SQL string. Keep the SQL text identical \
except for replacing interpolated values with placeholders.\n"
    );
    assert_eq!(
        default_py["example_before"],
        "cur.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n"
    );
    assert_eq!(
        default_py["example_after"],
        "cur.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n"
    );
}

#[test]
fn validator_hints_parses() {
    let v = parse_fixture("validator_hints.yaml");
    assert!(v.is_object());
}

#[test]
fn every_fixture_round_trips_through_serde_json_without_panicking() {
    for name in [
        "default.yaml",
        "sdk.yaml",
        "full.yaml",
        "design_controls.example.yaml",
        "remediation_policy.yaml.example",
        "remediation_playbook.yaml",
        "validator_hints.yaml",
    ] {
        let v = parse_fixture(name);
        let s = serde_json::to_string(&v).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!s.is_empty());
    }
}
