//! External-context injection loaders, ported from
//! `injectors/cve_feed.py::load_cves` (L26-76) and
//! `injectors/design_controls.py::load_controls` (L25-49).
//!
//! Every stage prompt that consumes injected context was already ported —
//! `bc-stage-s1/src/prompts.rs` (the "Known CVEs already filed" block),
//! `bc-stage-s2`'s threat-model user prompt, `bc-stage-s3`'s
//! `KNOWN CVEs … DO NOT REDISCOVER` / `DESIGN CONTROLS` context blocks,
//! `bc-stage-s4`'s per-chunk `related_cves` section, `bc-stage-s6`'s
//! control-aware verification prompt and `bc-stage-s8`'s chain prompt —
//! but nothing ever *filled* `ScanInput::known_cves` /
//! `ScanInput::design_controls`, so all six sections rendered as "(none)"
//! or were skipped entirely. These two loaders are the missing producer;
//! the CLI wires them to `inject.cve_file` / `inject.controls_file`
//! (Python: `orchestrator/scan.py:210-211`, resolved against the *config*
//! directory, not the scanned repo).
//!
//! **Why the two loaders degrade differently** — this asymmetry is
//! deliberate in the Python original, not an oversight, and is preserved
//! here:
//!
//! - The **CVE feed** isolates per-record validation (`cve_feed.py:62-76`):
//!   one malformed entry in a shared / hand-edited tracker export drops
//!   only itself and is logged, because suppressing the *whole* feed would
//!   silently turn "do not re-flag these known CVEs" back into "rediscover
//!   everything", which is the more expensive failure.
//! - The **controls file** is all-or-nothing (`design_controls.py:39-42`
//!   builds the list inside the guarded block): a design-control file is a
//!   small hand-authored security assertion, and half-loading it would
//!   downrank exploitability using a control set the author never wrote.
//!
//! Both reject a network (UNC / `\\host\share`) path before any filesystem
//! touch, matching `bc-config`/`bc-compliance`/`bc-enrich`'s handling of
//! config-supplied paths — merely *resolving* such a path on Windows
//! triggers an SMB handshake that leaks the caller's NTLMv2 hash.
//!
//! **Deliberate deviation from Python**: a *structural* failure (unreadable
//! file, bad JSON/YAML, wrong top-level shape) returns `Err` here instead of
//! printing to stderr and returning `[]`. The Python original's
//! print-and-continue is a side effect buried in a library function; making
//! it a `Result` lets the caller decide (the CLI logs a warning and
//! continues with no injected context, exactly like Python) while a test —
//! or a future strict mode — can still tell "file absent" from "file
//! present but broken". A *missing* file is still `Ok(vec![])` with no
//! diagnostic at all, matching `if not p.exists(): return []`.

use std::path::Path;

use bc_model::{Control, Cve};
use serde_json::Value;

/// Reject network paths before touching the filesystem, then read the file.
/// `Ok(None)` means "no such file" — the caller's cue to return an empty
/// list silently (Python: `if not p.exists(): return []`).
fn read_optional(path: &Path) -> Result<Option<String>, String> {
    if bc_pathjail::is_network_path(&path.to_string_lossy()) {
        return Err(format!("{}: network paths are not allowed", path.display()));
    }
    if !path.exists() {
        return Ok(None);
    }
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Unwrap the `{"cves": [...]}` / `{controls: [...]}` envelope Python
/// accepts alongside a bare list.
///
/// A mapping is only treated as a wrapper when it actually carries `key` —
/// otherwise Python would iterate the dict's *string keys* and then fail
/// every item's validation, so a keyless mapping is malformed input rather
/// than a single record (`cve_feed.py:36-46`). A non-list payload is
/// rejected explicitly rather than iterated char-by-char
/// (`cve_feed.py:47-52`).
fn unwrap_items(data: Value, key: &str, what: &str) -> Result<Vec<Value>, String> {
    let items = match data {
        Value::Object(mut map) => map.remove(key).ok_or_else(|| {
            format!(
                "{what} is a mapping without a '{key}' key — expected a list or {{{key}: [...]}}"
            )
        })?,
        other => other,
    };
    match items {
        Value::Array(items) => Ok(items),
        // `yaml.safe_load(...) or {}` turns an empty controls file into an
        // empty mapping, which the wrapper check above already rejects;
        // an explicit `controls:` with nothing under it parses to null and
        // means "no controls", not "malformed".
        Value::Null => Ok(Vec::new()),
        other => Err(format!(
            "{what} payload must be a list, got {}",
            type_name_of(&other)
        )),
    }
}

/// Python's `type(x).__name__`, used verbatim in both loaders' warnings so
/// operators reading a Rust log see the same wording as the Python tool.
fn type_name_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if n.is_f64() {
                "float"
            } else {
                "int"
            }
        }
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Load a known-CVE feed (JSON), ported from `cve_feed.py:26-76`.
///
/// Accepts a bare `[...]` list or a `{"cves": [...]}` wrapper — the example
/// feed shipped with the Python tool (`inputs/known_cves.example.json`)
/// uses the wrapper form and carries an extra `_license` key alongside it,
/// so unknown top-level keys are ignored rather than rejected.
///
/// **JSON only**, matching Python (`json.loads`); the controls file is the
/// YAML one. A missing file yields `Ok(vec![])`. Individual malformed
/// records are dropped and logged (`tracing::warn!`, standing in for
/// Python's stderr `[inject] WARN` + `errlog`), never failing the load.
pub fn load_known_cves(path: &Path) -> Result<Vec<Cve>, String> {
    let Some(text) = read_optional(path)? else {
        return Ok(Vec::new());
    };
    let data: Value = serde_json::from_str(&text)
        .map_err(|e| format!("{}: invalid JSON ({e})", path.display()))?;
    let items =
        unwrap_items(data, "cves", "CVE feed").map_err(|e| format!("{}: {e}", path.display()))?;

    let mut out = Vec::with_capacity(items.len());
    let mut skipped = 0usize;
    for (idx, item) in items.into_iter().enumerate() {
        let id = item.get("id").and_then(Value::as_str).map(str::to_string);
        match serde_json::from_value::<Cve>(item) {
            Ok(cve) => out.push(cve),
            Err(e) => {
                skipped += 1;
                let unit = match &id {
                    Some(id) => format!("{}#{idx} ({id})", path.display()),
                    None => format!("{}#{idx}", path.display()),
                };
                tracing::warn!("[inject] skipping malformed CVE record {unit}: {e}");
            }
        }
    }
    if skipped > 0 {
        // Formatted eagerly rather than through `warn!`'s own arguments:
        // `tracing`'s macros only evaluate their args when a subscriber
        // has the callsite enabled, so inlining them would make this
        // summary's arithmetic invisible to both the test suite and to
        // coverage.
        let summary = format!(
            "[inject] skipped {skipped} malformed CVE record(s) in {}; loaded {} valid record(s).",
            path.display(),
            out.len()
        );
        tracing::warn!("{summary}");
    }
    Ok(out)
}

/// Load design controls (YAML), ported from `design_controls.py:25-49`.
///
/// Accepts a bare list of mappings or a `{controls: [...]}` wrapper — the
/// example file shipped with the Python tool
/// (`inputs/design_controls.example.yaml`, mirrored at
/// `bc-yaml/tests/fixtures/design_controls.example.yaml`) uses the wrapper
/// form. A missing file yields `Ok(vec![])`; any malformed record fails the
/// whole load (see this module's header for why that differs from the CVE
/// feed).
///
/// `kind` is coerced through `bc_model`'s alias table (`authz` → `auth`,
/// `seccomp` → `sandbox`, anything unrecognized → `other`), so an operator
/// writing a plausible synonym gets a usable control rather than an error.
pub fn load_design_controls(path: &Path) -> Result<Vec<Control>, String> {
    let Some(text) = read_optional(path)? else {
        return Ok(Vec::new());
    };
    let data =
        bc_yaml::parse(&text).map_err(|e| format!("{}: invalid YAML ({e})", path.display()))?;
    let items = unwrap_items(data, "controls", "controls file")
        .map_err(|e| format!("{}: {e}", path.display()))?;

    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.into_iter().enumerate() {
        let control = serde_json::from_value::<Control>(item)
            .map_err(|e| format!("{}#{idx}: {e}", path.display()))?;
        out.push(control);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::ControlKind;

    fn write(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    // ── load_known_cves ──────────────────────────────────────────────

    #[test]
    fn cves_bare_list_loads() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            &d,
            "f.json",
            r#"[{"id":"CVE-1","summary":"s","affected_files":["a.c"],"cvss":7.5,"patched":true}]"#,
        );
        let got = load_known_cves(&p).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "CVE-1");
        assert_eq!(got[0].affected_files, vec!["a.c".to_string()]);
        assert_eq!(got[0].cvss, Some(7.5));
        assert!(got[0].patched);
    }

    #[test]
    fn cves_wrapper_dict_loads_and_ignores_sibling_keys() {
        // The shipped example feed carries a `_license` key next to `cves`.
        let d = tempfile::tempdir().unwrap();
        let p = write(
            &d,
            "f.json",
            r#"{"_license":"Apache-2.0","cves":[{"id":"CVE-2","summary":"x"}]}"#,
        );
        let got = load_known_cves(&p).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "CVE-2");
        assert!(got[0].affected_files.is_empty());
        assert_eq!(got[0].cvss, None);
        assert!(!got[0].patched);
    }

    #[test]
    fn cves_shipped_example_feed_parses() {
        // The real file from the Python tool, copied into bc-yaml's fixture
        // dir for the controls half; the CVE half is inlined here verbatim.
        let d = tempfile::tempdir().unwrap();
        let p = write(
            &d,
            "known_cves.example.json",
            r#"{
  "_license": "Copyright 2026 Visa, Inc.",
  "cves": [
    {
      "id": "CVE-2024-EXAMPLE",
      "summary": "Heap overflow in parse_header() via crafted Content-Length",
      "affected_files": ["src/http/parser.c"],
      "cvss": 8.1,
      "patched": false
    }
  ]
}"#,
        );
        let got = load_known_cves(&p).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "CVE-2024-EXAMPLE");
        assert_eq!(got[0].affected_files, vec!["src/http/parser.c".to_string()]);
    }

    #[test]
    fn cves_missing_file_is_empty_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        let got = load_known_cves(&d.path().join("nope.json")).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn cves_invalid_json_errors() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "f.json", "{not json");
        let e = load_known_cves(&p).unwrap_err();
        assert!(e.contains("invalid JSON"), "{e}");
    }

    #[test]
    fn cves_mapping_without_cves_key_errors() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "f.json", r#"{"items":[]}"#);
        let e = load_known_cves(&p).unwrap_err();
        assert!(e.contains("without a 'cves' key"), "{e}");
    }

    #[test]
    fn cves_non_list_payload_errors_with_python_type_name() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "f.json", r#"{"cves":123}"#);
        let e = load_known_cves(&p).unwrap_err();
        assert!(e.contains("must be a list, got int"), "{e}");
        let p2 = write(&d, "g.json", r#""hello""#);
        let e2 = load_known_cves(&p2).unwrap_err();
        assert!(e2.contains("must be a list, got str"), "{e2}");
    }

    #[test]
    fn type_names_match_pythons_type_name_for_every_json_kind() {
        // `unwrap_items` handles null / list / mapping before it ever needs
        // a name for them, so those three arms are only reachable by
        // calling the helper directly — they exist so a future caller that
        // *can* hit them still prints Python's own wording.
        assert_eq!(type_name_of(&Value::Null), "NoneType");
        assert_eq!(type_name_of(&Value::Array(vec![])), "list");
        assert_eq!(type_name_of(&Value::Object(serde_json::Map::new())), "dict");
    }

    #[test]
    fn cves_scalar_payload_type_names_cover_every_json_kind() {
        let d = tempfile::tempdir().unwrap();
        for (body, want) in [
            ("true", "bool"),
            ("1.5", "float"),
            ("7", "int"),
            (r#""s""#, "str"),
        ] {
            let p = write(&d, "t.json", body);
            let e = load_known_cves(&p).unwrap_err();
            assert!(e.contains(&format!("got {want}")), "{body} -> {e}");
        }
    }

    #[test]
    fn cves_null_payload_is_empty() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "f.json", r#"{"cves":null}"#);
        assert!(load_known_cves(&p).unwrap().is_empty());
    }

    #[test]
    fn cves_partial_accept_keeps_valid_drops_bad() {
        // Python isolates per-record validation: one bad entry must not
        // suppress the rest of the feed.
        let d = tempfile::tempdir().unwrap();
        let p = write(
            &d,
            "f.json",
            // Three flavors of bad record: one with no `id` at all, one
            // that isn't an object, and one that HAS an id but a
            // wrong-typed field — Python names the id in its per-item
            // skip log when it can find one, so both spellings of the
            // diagnostic are exercised here.
            r#"[{"id":"CVE-A","summary":"ok"},
                {"summary":"missing id"},
                "not-an-object",
                {"id":"CVE-BAD","summary":123},
                {"id":"CVE-B","summary":"ok too"}]"#,
        );
        let got = load_known_cves(&p).unwrap();
        assert_eq!(
            got.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["CVE-A", "CVE-B"]
        );
    }

    #[test]
    fn cves_reject_network_path() {
        let e = load_known_cves(Path::new(r"\\attacker\share\f.json")).unwrap_err();
        assert!(e.contains("network paths are not allowed"), "{e}");
    }

    #[test]
    fn cves_unreadable_path_errors() {
        // A directory exists but cannot be read as a string.
        let d = tempfile::tempdir().unwrap();
        let e = load_known_cves(d.path()).unwrap_err();
        assert!(!e.is_empty());
        assert!(!e.contains("invalid JSON"), "{e}");
    }

    // ── load_design_controls ─────────────────────────────────────────

    #[test]
    fn controls_wrapper_mapping_loads() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            &d,
            "c.yaml",
            "controls:\n  - name: gw\n    kind: auth\n    protects:\n      - \"src/**\"\n    notes: n\n",
        );
        let got = load_design_controls(&p).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "gw");
        assert_eq!(got[0].kind, ControlKind::Auth);
        assert_eq!(got[0].protects, vec!["src/**".to_string()]);
        assert_eq!(got[0].notes, "n");
    }

    #[test]
    fn controls_bare_list_loads() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "c.yaml", "- name: s\n  kind: seccomp\n");
        let got = load_design_controls(&p).unwrap();
        assert_eq!(got.len(), 1);
        // `seccomp` is an alias for `sandbox` in bc_model's coercion table.
        assert_eq!(got[0].kind, ControlKind::Sandbox);
        assert!(got[0].protects.is_empty());
    }

    #[test]
    fn controls_unknown_kind_coerces_to_other() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "c.yaml", "- name: x\n  kind: quantum-shield\n");
        let got = load_design_controls(&p).unwrap();
        assert_eq!(got[0].kind, ControlKind::Other);
    }

    #[test]
    fn controls_shipped_example_file_parses() {
        // Same file the bc-yaml fixture suite parses
        // (bc-yaml/tests/fixtures/design_controls.example.yaml).
        let fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bc-yaml/tests/fixtures/design_controls.example.yaml"
        );
        let got = load_design_controls(Path::new(fixture)).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].name, "api-gateway-auth");
        assert_eq!(got[0].kind, ControlKind::Auth);
        assert_eq!(got[0].protects, vec!["src/handlers/**".to_string()]);
        assert_eq!(got[1].name, "seccomp-sandbox");
        assert_eq!(got[1].kind, ControlKind::Sandbox);
    }

    #[test]
    fn controls_missing_file_is_empty_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        assert!(load_design_controls(&d.path().join("nope.yaml"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn controls_empty_file_is_empty() {
        // `yaml.safe_load("") or {}` -> {} -> no `controls` key. Python
        // raises and degrades to []; here an empty document parses to null,
        // which unwrap_items treats as "no controls".
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "c.yaml", "controls:\n");
        assert!(load_design_controls(&p).unwrap().is_empty());
    }

    #[test]
    fn controls_mapping_without_controls_key_errors() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "c.yaml", "items: []\n");
        let e = load_design_controls(&p).unwrap_err();
        assert!(e.contains("without a 'controls' key"), "{e}");
    }

    #[test]
    fn controls_non_list_payload_errors() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "c.yaml", "controls: 5\n");
        let e = load_design_controls(&p).unwrap_err();
        assert!(e.contains("must be a list, got int"), "{e}");
    }

    #[test]
    fn controls_malformed_record_fails_the_whole_load() {
        // Deliberately unlike the CVE feed — see the module header.
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "c.yaml", "- name: ok\n  kind: auth\n- kind: auth\n");
        let e = load_design_controls(&p).unwrap_err();
        assert!(e.contains("#1"), "{e}");
    }

    #[test]
    fn controls_invalid_yaml_errors() {
        let d = tempfile::tempdir().unwrap();
        let p = write(&d, "c.yaml", "controls: [ {name: a, kind: auth}\n");
        let e = load_design_controls(&p).unwrap_err();
        assert!(e.contains("invalid YAML"), "{e}");
    }

    #[test]
    fn controls_reject_network_path() {
        let e = load_design_controls(Path::new("//attacker/share/c.yaml")).unwrap_err();
        assert!(e.contains("network paths are not allowed"), "{e}");
    }

    #[test]
    fn controls_unreadable_path_errors() {
        let d = tempfile::tempdir().unwrap();
        let e = load_design_controls(d.path()).unwrap_err();
        assert!(!e.contains("invalid YAML"), "{e}");
    }
}
