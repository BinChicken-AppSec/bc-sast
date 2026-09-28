//! The one-line `config.local.yaml` provenance banner, ported from
//! `vvaharness/config/__init__.py`'s `_leaf_paths`, `_override_entry` and
//! the "config overlay: ... applied (overrides: ...)" print in `load()`.
//!
//! The overlay is merged silently otherwise, so the banner names every
//! leaf key it overrides. How much of each value is shown depends on what
//! the key could hold:
//! - credential or command keys show only `(set)`/`(unset)`,
//! - URLs show the host only, never the userinfo, path or query,
//! - a short allowlist of routing keys that are safe and useful to see
//!   (model ids, TLS knobs, tool lists) shows the value,
//! - everything else shows just the key name, as Python does.
//!
//! Pure: [`crate::load`] records what the overlay overrode and the CLI
//! decides where (and how often) to print the rendered line.

use serde_json::Value;

use crate::policy::{is_secret_var_name, CREDENTIAL_DESTINATIONS};
use crate::LocalOverlayStatus;

/// Leaf names (the last dotted segment) whose resolved value is printed.
/// Python's `TLS_ROUTING_KEYS` plus this port's tool-permission lists.
const VALUE_LEAVES: &[&str] = &[
    "verify_ssl",
    "ca_cert",
    "client_cert",
    "no_proxy",
    "cache_route",
    "allowed_tools",
];

/// Full key paths whose resolved value is printed.
const VALUE_PATHS: &[&str] = &["pricing.provider", "step_remediate.enforce_policy"];

/// A printed value is cut to this many characters so one enormous list
/// cannot flood the terminal.
const MAX_VALUE_CHARS: usize = 120;

/// Dotted key paths of every leaf (non-object, or empty-object) value in
/// `tree`, in document order. Lists are leaves, as in Python.
pub(crate) fn leaf_paths(tree: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_leaves(tree, "", &mut out);
    out
}

fn collect_leaves(node: &Value, prefix: &str, out: &mut Vec<String>) {
    match node {
        Value::Object(map) if !map.is_empty() => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                collect_leaves(v, &path, out);
            }
        }
        _ => out.push(prefix.to_string()),
    }
}

/// The banner line for `status`, rendered against the fully merged and
/// expanded tree `resolved` (so a host or value is the one that will
/// actually be used). `None` when there is no overlay to announce.
pub fn render_overlay_banner(status: &LocalOverlayStatus, resolved: &Value) -> Option<String> {
    match status {
        LocalOverlayStatus::Absent => None,
        LocalOverlayStatus::Skipped { path } => Some(format!(
            "config overlay: {} present but SKIPPED (BC_NO_LOCAL_CONFIG set)",
            path.display()
        )),
        LocalOverlayStatus::Applied {
            path,
            overridden_leaves,
            ownership_verified,
        } => {
            let mut leaves: Vec<&String> = overridden_leaves.iter().collect();
            leaves.sort();
            let entries: Vec<String> = leaves
                .into_iter()
                .map(|leaf| render_entry(leaf, resolved))
                .collect();
            let overrides = if entries.is_empty() {
                "(empty)".to_string()
            } else {
                entries.join(", ")
            };
            let unverified = if *ownership_verified {
                ""
            } else {
                "; ownership unverified (non-POSIX platform)"
            };
            Some(format!(
                "config overlay: {} applied (overrides: {overrides}){unverified}",
                path.display()
            ))
        }
    }
}

fn resolved_leaf<'a>(data: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(data, |node, seg| node.get(seg))
}

fn render_entry(path: &str, resolved: &Value) -> String {
    let value = resolved_leaf(resolved, path);
    if hides_value(path) {
        let set = value.is_some_and(|v| !v.is_null() && v.as_str() != Some(""));
        return format!("{path} ({})", if set { "set" } else { "unset" });
    }
    let as_str = value.and_then(Value::as_str);
    if is_endpoint(path, as_str) {
        let host = as_str.and_then(url_host).unwrap_or("(no host)");
        return format!("{path} -> {host}");
    }
    match value {
        Some(v) if shows_value(path) => format!("{path}={}", bounded(v)),
        _ => path.to_string(),
    }
}

/// A credential destination, anything whose name reads like a secret
/// (the same name patterns the interpolation policy uses), or a command
/// line (`step_remediate.verify_command`), which can embed a secret.
fn hides_value(path: &str) -> bool {
    CREDENTIAL_DESTINATIONS.contains(&path)
        || is_secret_var_name(path)
        || last_segment(path).ends_with("command")
}

fn is_endpoint(path: &str, value: Option<&str>) -> bool {
    let leaf = last_segment(path);
    leaf.ends_with("url") || leaf.ends_with("endpoint") || value.is_some_and(|s| s.contains("://"))
}

fn shows_value(path: &str) -> bool {
    let leaf = last_segment(path);
    let is_model_id =
        path.starts_with("models.") && (leaf == "id" || path.matches('.').count() == 1);
    is_model_id || VALUE_LEAVES.contains(&leaf) || VALUE_PATHS.contains(&path)
}

fn last_segment(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

fn bounded(v: &Value) -> String {
    let text = match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    if text.chars().count() <= MAX_VALUE_CHARS {
        return text;
    }
    let cut: String = text.chars().take(MAX_VALUE_CHARS).collect();
    format!("{cut}...")
}

/// The host (and port) of a `scheme://` URL, with any userinfo dropped.
/// `None` when there is no host or the authority is ambiguous (an `@`
/// after the first `/`, `?` or `#`, or a non-numeric "port", both of
/// which suggest an unescaped credential), so the caller prints
/// `(no host)` rather than guessing and leaking part of a password.
fn url_host(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if tail.contains('@') {
        return None;
    }
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let port_ok = match host.rsplit_once(':') {
        // The colons inside a bare IPv6 literal (`[::1]`), not a port.
        Some((h, _)) if h.starts_with('[') && !h.ends_with(']') => true,
        Some((_, port)) => !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
        None => true,
    };
    (!host.is_empty() && port_ok).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;
    use std::path::PathBuf;

    fn applied(leaves: &[&str], verified: bool) -> LocalOverlayStatus {
        LocalOverlayStatus::Applied {
            path: PathBuf::from("/cfg/config.local.yaml"),
            overridden_leaves: leaves.iter().map(|s| s.to_string()).collect(),
            ownership_verified: verified,
        }
    }

    #[test]
    fn leaf_paths_walks_nested_objects_and_treats_lists_and_empty_maps_as_leaves() {
        let tree = json!({"a": {"b": 1, "c": [1, 2], "d": {}}, "e": "x"});
        assert_eq!(leaf_paths(&tree), vec!["a.b", "a.c", "a.d", "e"]);
    }

    #[test]
    fn absent_renders_nothing() {
        assert_eq!(
            render_overlay_banner(&LocalOverlayStatus::Absent, &json!({})),
            None
        );
    }

    #[test]
    fn skipped_names_the_escape_hatch() {
        let status = LocalOverlayStatus::Skipped {
            path: PathBuf::from("/cfg/config.local.yaml"),
        };
        let line = render_overlay_banner(&status, &json!({})).unwrap();
        assert!(line.contains("/cfg/config.local.yaml"), "{line}");
        assert!(line.contains("SKIPPED (BC_NO_LOCAL_CONFIG set)"), "{line}");
    }

    #[test]
    fn an_empty_overlay_says_so() {
        let line = render_overlay_banner(&applied(&[], true), &json!({})).unwrap();
        assert!(line.ends_with("applied (overrides: (empty))"), "{line}");
    }

    #[test]
    fn unverified_ownership_is_called_out() {
        let line = render_overlay_banner(&applied(&[], false), &json!({})).unwrap();
        assert!(line.contains("ownership unverified"), "{line}");
    }

    #[test]
    fn entries_are_sorted_and_each_class_gets_its_own_visibility() {
        let resolved = json!({
            "step_remediate": {
                "verify_command": "make test TOKEN=abc",
                "enforce_policy": true,
                "allowed_tools": ["Read", "Edit"],
            },
            "models": {"deepdive": {"id": "opus", "temperature": 0.2}, "verify": "sonnet"},
            "pricing": {"provider": "anthropic"},
            "gateway": {"base_url": "https://user:pw@gw.example.com:8443/v1?key=zzz"},
            "step1": {"max_turns": 60},
        });
        let leaves = [
            "step1.max_turns",
            "step_remediate.verify_command",
            "step_remediate.enforce_policy",
            "step_remediate.allowed_tools",
            "models.deepdive.id",
            "models.deepdive.temperature",
            "models.verify",
            "pricing.provider",
            "gateway.base_url",
        ];
        let line = render_overlay_banner(&applied(&leaves, true), &resolved).unwrap();
        let overrides = line.split_once("(overrides: ").unwrap().1;
        assert_eq!(
            overrides,
            "gateway.base_url -> gw.example.com:8443, models.deepdive.id=opus, \
             models.deepdive.temperature, models.verify=sonnet, pricing.provider=anthropic, \
             step1.max_turns, step_remediate.allowed_tools=[\"Read\",\"Edit\"], \
             step_remediate.enforce_policy=true, step_remediate.verify_command (set))"
        );
        assert!(!line.contains("pw"), "{line}");
        assert!(!line.contains("zzz"), "{line}");
        assert!(!line.contains("make test"), "{line}");
    }

    #[rstest]
    #[case(json!({"x": {"api_key": "sk-live"}}), "x.api_key", "x.api_key (set)")]
    #[case(json!({"x": {"api_key": ""}}), "x.api_key", "x.api_key (unset)")]
    #[case(json!({"x": {"api_key": null}}), "x.api_key", "x.api_key (unset)")]
    #[case(json!({}), "x.oauth", "x.oauth (unset)")]
    #[case(json!({"x": {"run_command": "echo hi"}}), "x.run_command", "x.run_command (set)")]
    fn secret_and_command_keys_show_only_presence(
        #[case] resolved: Value,
        #[case] path: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(render_entry(path, &resolved), expected);
    }

    #[rstest]
    // A URL value is host-only whatever its key is called.
    #[case(json!({"a": {"b": "http://h.example/p"}}), "a.b", "a.b -> h.example")]
    // A URL-named key without a parseable URL never prints its value.
    #[case(json!({"a": {"ingest_url": "not a url"}}), "a.ingest_url", "a.ingest_url -> (no host)")]
    #[case(json!({"a": {"endpoint": 5}}), "a.endpoint", "a.endpoint -> (no host)")]
    #[case(json!({}), "a.base_url", "a.base_url -> (no host)")]
    fn endpoints_show_the_host_only(
        #[case] resolved: Value,
        #[case] path: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(render_entry(path, &resolved), expected);
    }

    #[test]
    fn a_value_key_whose_value_is_missing_shows_just_its_name() {
        assert_eq!(
            render_entry("pricing.provider", &json!({})),
            "pricing.provider"
        );
    }

    #[test]
    fn tls_leaves_show_their_value() {
        let resolved = json!({"llm": {"verify_ssl": false}});
        assert_eq!(
            render_entry("llm.verify_ssl", &resolved),
            "llm.verify_ssl=false"
        );
    }

    #[test]
    fn a_long_value_is_bounded() {
        let long = "m".repeat(MAX_VALUE_CHARS + 10);
        let resolved = json!({"models": {"x": {"id": long}}});
        let entry = render_entry("models.x.id", &resolved);
        assert!(entry.ends_with("..."), "{entry}");
        assert_eq!(entry.len(), "models.x.id=".len() + MAX_VALUE_CHARS + 3);
    }

    #[test]
    fn a_models_leaf_deeper_than_a_role_that_is_not_an_id_is_name_only() {
        let resolved = json!({"models": {"validate": {"orchestrator": {"seed": 1}}}});
        assert_eq!(
            render_entry("models.validate.orchestrator.seed", &resolved),
            "models.validate.orchestrator.seed"
        );
    }

    #[rstest]
    #[case("https://gw.example.com", Some("gw.example.com"))]
    #[case("https://gw.example.com:443/v1", Some("gw.example.com:443"))]
    #[case("https://user:pw@gw.example.com/v1", Some("gw.example.com"))]
    #[case("https://[::1]:8080/x", Some("[::1]:8080"))]
    #[case("https://[::1]:abc/x", None)]
    #[case("https://[::1]/x", Some("[::1]"))]
    #[case("https://gw.example.com?token=abc", Some("gw.example.com"))]
    #[case("https://gw.example.com#frag", Some("gw.example.com"))]
    // An unescaped '/' in a password makes the authority ambiguous.
    #[case("https://user:pa/ss@gw.example.com", None)]
    // A non-numeric "port" is most likely user:password without a host.
    #[case("https://user:password", None)]
    #[case("https://host:", None)]
    #[case("https://", None)]
    #[case("https:///path", None)]
    #[case("no scheme here", None)]
    fn url_host_cases(#[case] url: &str, #[case] expected: Option<&str>) {
        assert_eq!(url_host(url), expected);
    }
}
