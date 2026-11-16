use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

const GENERIC_KB_YAML: &str = include_str!("../corpus/generic.kb.yaml");

#[derive(Debug, Clone, Default)]
struct KbEntry {
    cwe: String,
    title: String,
    origin: Vec<String>,
    sources: Vec<String>,
    sinks: Vec<String>,
    sanitizers: Vec<String>,
    non_sanitizers: Vec<String>,
    fp_checks: Vec<String>,
}

fn norm_cwe(s: &str) -> Option<String> {
    let caps = CWE_RE.captures(s)?;
    let digits: i64 = caps[1].parse().ok()?;
    Some(format!("CWE-{digits}"))
}

fn str_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn push_unique(list: &mut Vec<String>, v: String) {
    if !v.is_empty() && !list.contains(&v) {
        list.push(v);
    }
}

fn merge_entry(by_cwe: &mut BTreeMap<String, KbEntry>, entry: &Value) {
    let Some(cwe) = entry.get("cwe").and_then(Value::as_str).and_then(norm_cwe) else {
        return;
    };
    let slot = by_cwe.entry(cwe.clone()).or_insert_with(|| KbEntry {
        cwe: cwe.clone(),
        ..Default::default()
    });
    if slot.title.is_empty() {
        if let Some(t) = entry.get("title").and_then(Value::as_str) {
            slot.title = t.trim().to_string();
        }
    }
    if let Some(o) = entry.get("origin").and_then(Value::as_str) {
        push_unique(&mut slot.origin, o.trim().to_string());
    }
    for v in str_list(entry.get("sources")) {
        push_unique(&mut slot.sources, v);
    }
    for v in str_list(entry.get("sinks")) {
        push_unique(&mut slot.sinks, v);
    }
    for v in str_list(entry.get("sanitizers")) {
        push_unique(&mut slot.sanitizers, v);
    }
    for v in str_list(entry.get("non_sanitizers")) {
        push_unique(&mut slot.non_sanitizers, v);
    }
    for v in str_list(entry.get("fp_checks")) {
        push_unique(&mut slot.fp_checks, v);
    }
}

fn parse_kb(yaml_text: &str) -> BTreeMap<String, KbEntry> {
    let mut by_cwe = BTreeMap::new();
    let Ok(doc) = appsec_yaml::parse(yaml_text) else {
        return by_cwe;
    };
    let Some(entries) = doc.get("entries").and_then(Value::as_array) else {
        return by_cwe;
    };
    for entry in entries {
        if entry.is_object() {
            merge_entry(&mut by_cwe, entry);
        }
    }
    by_cwe
}

static KB: LazyLock<BTreeMap<String, KbEntry>> = LazyLock::new(|| parse_kb(GENERIC_KB_YAML));

static CWE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)CWE[-_ ]?0*(\d{1,4})").unwrap());

static LANG_PREFIX_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([a-z][a-z0-9_+-]{0,15}):\s+(.+)$").unwrap());

fn filter_lang(items: &[String], lang: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for it in items {
        let text = match LANG_PREFIX_RX.captures(it) {
            Some(caps) => {
                let prefix = &caps[1];
                if lang.is_some_and(|l| l != prefix) {
                    continue;
                }
                caps[2].to_string()
            }
            None => it.clone(),
        };
        push_unique(&mut out, text);
    }
    out
}

#[derive(Debug, Default)]
struct KbContext {
    cwe: Vec<String>,
    title: Vec<String>,
    origin: Vec<String>,
    sources: Vec<String>,
    sinks: Vec<String>,
    sanitizers: Vec<String>,
    non_sanitizers: Vec<String>,
    fp_checks: Vec<String>,
}

fn for_cwes(cwes: &[String], lang: Option<&str>) -> KbContext {
    let mut out = KbContext::default();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for c in cwes {
        let Some(cn) = norm_cwe(c) else { continue };
        let Some(slot) = KB.get(&cn) else { continue };
        if !seen.insert(cn) {
            continue;
        }
        out.cwe.push(slot.cwe.clone());
        if !slot.title.is_empty() {
            out.title.push(slot.title.clone());
        }
        for o in &slot.origin {
            push_unique(&mut out.origin, o.clone());
        }
        for v in filter_lang(&slot.sources, lang) {
            push_unique(&mut out.sources, v);
        }
        for v in filter_lang(&slot.sinks, lang) {
            push_unique(&mut out.sinks, v);
        }
        for v in filter_lang(&slot.sanitizers, lang) {
            push_unique(&mut out.sanitizers, v);
        }
        for v in filter_lang(&slot.non_sanitizers, lang) {
            push_unique(&mut out.non_sanitizers, v);
        }
        for v in filter_lang(&slot.fp_checks, lang) {
            push_unique(&mut out.fp_checks, v);
        }
    }
    out
}

const LIST_LIMIT: usize = 20;

pub fn prompt_block(cwes: &[String], lang: Option<&str>) -> String {
    render(&for_cwes(cwes, lang))
}

fn render(ctx: &KbContext) -> String {
    let any = !ctx.sources.is_empty()
        || !ctx.sinks.is_empty()
        || !ctx.sanitizers.is_empty()
        || !ctx.non_sanitizers.is_empty()
        || !ctx.fp_checks.is_empty();
    if !any {
        return String::new();
    }
    let title = if !ctx.title.is_empty() {
        ctx.title.join(" / ")
    } else {
        ctx.cwe.join(", ")
    };
    let mut head = format!("TAINT KB — {title}");
    if !ctx.origin.is_empty() {
        head.push_str(&format!("  (origin: {})", ctx.origin.join(", ")));
    }
    let mut lines = vec![head];
    let labeled: [(&str, &[String]); 4] = [
        (
            "SANITIZERS — if ANY of these sits on the path, REFUTE:",
            &ctx.sanitizers,
        ),
        (
            "NON-SANITIZERS — these look safe but are NOT; do NOT refute on \
             their basis alone:",
            &ctx.non_sanitizers,
        ),
        ("FP CHECKS — if ANY is true, REFUTE:", &ctx.fp_checks),
        (
            "KNOWN SINKS — for reference; the candidate sink should match \
             one of these shapes:",
            &ctx.sinks,
        ),
    ];
    for (label, items) in labeled {
        if items.is_empty() {
            continue;
        }
        lines.push(format!("  {label}"));
        lines.extend(
            items
                .iter()
                .take(LIST_LIMIT)
                .map(|it| format!("    - {it}")),
        );
        if items.len() > LIST_LIMIT {
            lines.push(format!("    - …(+{} more)", items.len() - LIST_LIMIT));
        }
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cwes(vals: &[&str]) -> Vec<String> {
        vals.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn norm_cwe_accepts_common_forms() {
        assert_eq!(norm_cwe("CWE-89"), Some("CWE-89".to_string()));
        assert_eq!(norm_cwe("cwe-89"), Some("CWE-89".to_string()));
        assert_eq!(norm_cwe("cwe_089"), Some("CWE-89".to_string()));
        assert_eq!(norm_cwe("CWE 89"), Some("CWE-89".to_string()));
        assert_eq!(norm_cwe("89"), None);
        assert_eq!(norm_cwe(""), None);
        assert_eq!(norm_cwe("not-a-cwe"), None);
    }

    #[test]
    fn embedded_corpus_parses_and_merges_duplicate_cwe_ids() {
        assert_eq!(KB.len(), 24);
        let cwe117 = KB.get("CWE-117").unwrap();
        assert_eq!(
            cwe117.title,
            "OWASP A09 logging / monitoring: log injection"
        );
        assert!(cwe117
            .sources
            .iter()
            .any(|s| s.contains("user-controlled strings")));
        assert!(cwe117.sources.iter().any(|s| s.contains("PII")));
        assert_eq!(cwe117.origin, vec!["generic".to_string()]);
    }

    #[test]
    fn prompt_block_is_empty_for_an_unknown_cwe() {
        assert_eq!(prompt_block(&cwes(&["CWE-99999"]), None), "");
    }

    #[test]
    fn prompt_block_is_empty_for_no_cwes() {
        assert_eq!(prompt_block(&[], None), "");
    }

    #[test]
    fn prompt_block_renders_a_known_cwe() {
        let block = prompt_block(&cwes(&["CWE-89"]), None);
        assert!(block.starts_with("TAINT KB — SQL Injection  (origin: generic)\n"));
        assert!(block.contains("SANITIZERS — if ANY of these sits on the path, REFUTE:"));
        assert!(block.contains("Parameterized queries / prepared statements"));
        assert!(block.contains("NON-SANITIZERS"));
        assert!(block.contains("FP CHECKS — if ANY is true, REFUTE:"));
        assert!(block.contains("KNOWN SINKS"));
        assert!(block.ends_with('\n'));
    }

    #[test]
    fn prompt_block_requires_the_literal_cwe_prefix_a_bare_digit_matches_nothing() {
        assert_eq!(prompt_block(&cwes(&["89"]), None), "");
        assert_ne!(prompt_block(&cwes(&["CWE-89"]), None), "");
    }

    #[test]
    fn prompt_block_merges_multiple_cwes() {
        let block = prompt_block(&cwes(&["CWE-89", "CWE-78"]), None);
        assert!(
            block.starts_with("TAINT KB — SQL Injection / OWASP A03 Injection: command execution")
        );
    }

    #[test]
    fn prompt_block_dedups_a_repeated_cwe() {
        let once = prompt_block(&cwes(&["CWE-89"]), None);
        let twice = prompt_block(&cwes(&["CWE-89", "CWE-89"]), None);
        assert_eq!(once, twice);
    }

    #[test]
    fn prompt_block_lang_filter_strips_prefix_and_drops_other_languages() {
        let java_only = prompt_block(&cwes(&["CWE-89"]), Some("java"));
        assert!(java_only.contains("PreparedStatement"));
        assert!(!java_only.contains("java:"));

        let python_only = prompt_block(&cwes(&["CWE-89"]), Some("python"));
        assert!(python_only.contains("cursor.execute"));
        assert!(!python_only.contains("PreparedStatement"));
    }

    #[test]
    fn prompt_block_lang_none_keeps_every_language_variant() {
        let block = prompt_block(&cwes(&["CWE-89"]), None);
        assert!(block.contains("cursor.execute"));
        assert!(block.contains("PreparedStatement"));
    }

    #[test]
    fn render_truncates_a_long_list_with_a_more_suffix() {
        let ctx = KbContext {
            cwe: vec!["CWE-1".to_string()],
            title: vec!["Test".to_string()],
            sanitizers: (0..25).map(|i| format!("s{i}")).collect(),
            ..Default::default()
        };
        let block = render(&ctx);
        assert!(block.contains("- …(+5 more)"));
        assert_eq!(
            block.lines().filter(|l| l.starts_with("    - s")).count(),
            LIST_LIMIT
        );
    }

    #[test]
    fn render_falls_back_to_the_cwe_list_when_every_title_is_empty() {
        let ctx = KbContext {
            cwe: vec!["CWE-1".to_string(), "CWE-2".to_string()],
            sinks: vec!["some sink".to_string()],
            ..Default::default()
        };
        let block = render(&ctx);
        assert!(block.starts_with("TAINT KB — CWE-1, CWE-2\n"));
    }

    #[test]
    fn render_is_empty_when_only_sources_is_populated() {
        let ctx = KbContext {
            cwe: vec!["CWE-1".to_string()],
            title: vec!["Test".to_string()],
            sources: vec!["some source".to_string()],
            ..Default::default()
        };
        let block = render(&ctx);
        assert_eq!(block, "TAINT KB — Test\n");
    }

    #[test]
    fn merge_entry_first_title_wins_and_lists_union() {
        let mut by_cwe = BTreeMap::new();
        merge_entry(
            &mut by_cwe,
            &serde_json::json!({"cwe": "CWE-1", "title": "First", "sinks": ["a"]}),
        );
        merge_entry(
            &mut by_cwe,
            &serde_json::json!({"cwe": "CWE-1", "title": "Second", "sinks": ["a", "b"]}),
        );
        let slot = by_cwe.get("CWE-1").unwrap();
        assert_eq!(slot.title, "First");
        assert_eq!(slot.sinks, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn merge_entry_skips_an_entry_with_no_recognizable_cwe() {
        let mut by_cwe = BTreeMap::new();
        merge_entry(&mut by_cwe, &serde_json::json!({"title": "No CWE"}));
        assert!(by_cwe.is_empty());
    }

    #[test]
    fn parse_kb_degrades_to_empty_on_malformed_yaml() {
        assert!(parse_kb("not: [a, valid\n").is_empty());
    }

    #[test]
    fn parse_kb_degrades_to_empty_when_entries_key_is_absent() {
        assert!(parse_kb("other: stuff\n").is_empty());
    }

    #[test]
    fn parse_kb_skips_a_non_object_entry() {
        let kb = parse_kb("entries:\n  - just a string\n  - cwe: CWE-1\n");
        assert_eq!(kb.len(), 1);
    }

    #[test]
    fn filter_lang_keeps_unprefixed_and_matching_prefixed_items() {
        let items = vec![
            "generic item".to_string(),
            "java: JavaThing".to_string(),
            "python: PyThing".to_string(),
        ];
        let out = filter_lang(&items, Some("java"));
        assert_eq!(
            out,
            vec!["generic item".to_string(), "JavaThing".to_string()]
        );
    }

    #[test]
    fn filter_lang_none_keeps_and_strips_every_prefix() {
        let items = vec!["java: JavaThing".to_string(), "python: PyThing".to_string()];
        let out = filter_lang(&items, None);
        assert_eq!(out, vec!["JavaThing".to_string(), "PyThing".to_string()]);
    }
}
