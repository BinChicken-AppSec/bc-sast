use appsec_llm_client::capabilities::{self, Lifecycle, Provider};
use serde_json::Value;

pub(crate) fn configured_models(cli_model: &str, data: &Value) -> Vec<String> {
    let mut ids = vec![cli_model.to_string()];
    let mut push = |section: &Value| {
        if let Some(id) = section.get("id").and_then(Value::as_str) {
            if !ids.iter().any(|seen| seen == id) {
                ids.push(id.to_string());
            }
        }
    };
    if let Some(models) = data.get("models").and_then(Value::as_object) {
        for section in models.values() {
            push(section);
            if let Some(nested) = section.as_object() {
                nested.values().for_each(&mut push);
            }
        }
    }
    ids
}

pub(crate) fn suggested_replacement(model: &str) -> &'static str {
    let id = capabilities::normalize_model_id(model);
    match capabilities::capabilities(model).provider {
        Provider::Anthropic if id.contains("haiku") => "claude-haiku-4-5",
        Provider::Anthropic if id.contains("opus") => "claude-opus-5",
        Provider::Anthropic => "claude-sonnet-5",
        Provider::OpenAi | Provider::Unknown => crate::args::DEFAULT_MODEL,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GateReport {
    pub refused: Vec<String>,
    pub warnings: Vec<String>,
}

pub(crate) fn check(models: &[String], today: &str, allow_unsupported: bool) -> GateReport {
    let mut report = GateReport::default();
    for model in models {
        let replacement = suggested_replacement(model);
        match capabilities::lifecycle_on(model, today) {
            Lifecycle::Current => {}
            Lifecycle::Retired if allow_unsupported => report.warnings.push(format!(
                "model {model} is retired and no longer served by its provider; running \
                 anyway because of --allow-unsupported-model (suggested replacement: \
                 {replacement})"
            )),
            Lifecycle::Retired => report.refused.push(format!(
                "model {model} is retired and no longer served by its provider; use \
                 {replacement} instead, or pass --allow-unsupported-model if your gateway \
                 serves its own model under this name"
            )),
            other => report.warnings.push(format!(
                "model {model} is {}; consider {replacement}",
                other.label()
            )),
        }
    }
    report
}

pub(crate) fn enforce(
    cli_model: &str,
    data: &Value,
    allow_unsupported: bool,
) -> Result<(), String> {
    enforce_on(
        cli_model,
        data,
        allow_unsupported,
        &capabilities::today_utc(),
    )
}

fn enforce_on(
    cli_model: &str,
    data: &Value,
    allow_unsupported: bool,
    today: &str,
) -> Result<(), String> {
    let report = check(
        &configured_models(cli_model, data),
        today,
        allow_unsupported,
    );
    for warning in &report.warnings {
        eprintln!("  [model] WARN: {warning}");
    }
    if report.refused.is_empty() {
        Ok(())
    } else {
        Err(report.refused.join("\n"))
    }
}

pub(crate) fn render_capabilities(models: &[String], today: &str) -> String {
    models
        .iter()
        .map(|model| {
            format!(
                "  [model] {}",
                capabilities::capabilities(model).render(model, today)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TODAY: &str = "2026-09-25";

    #[test]
    fn configured_models_lists_the_flag_then_every_role_once() {
        let data = json!({"models": {
            "deepdive": {"id": "claude-opus-5"},
            "verify": {"id": "gpt-5.6-luna"},
            "chain": {"temperature": 0.0},
            "dedup": {"id": 7},
            "validate": {
                "orchestrator": {"id": "claude-sonnet-5"},
                "security_architect": {"id": "claude-opus-5"},
            },
            "odd": "scalar",
        }});
        assert_eq!(
            configured_models("gpt-5.6-luna", &data),
            ["gpt-5.6-luna", "claude-opus-5", "claude-sonnet-5"]
        );
        assert_eq!(configured_models("m", &Value::Null), ["m"]);
    }

    #[test]
    fn a_retired_model_is_refused_with_a_replacement_by_tier() {
        let report = check(
            &[
                "claude-3-opus-20240229".to_string(),
                "claude-3-haiku".to_string(),
                "claude-2.1".to_string(),
                "o1-mini".to_string(),
            ],
            TODAY,
            false,
        );
        assert!(report.warnings.is_empty());
        assert_eq!(report.refused.len(), 4);
        assert!(report.refused[0].contains("claude-3-opus-20240229 is retired"));
        assert!(report.refused[0].contains("use claude-opus-5 instead"));
        assert!(report.refused[1].contains("use claude-haiku-4-5 instead"));
        assert!(report.refused[2].contains("use claude-sonnet-5 instead"));
        assert!(report.refused[3].contains(&format!("use {} instead", crate::args::DEFAULT_MODEL)));
        assert!(report.refused[0].contains("--allow-unsupported-model"));
    }

    #[test]
    fn allowing_unsupported_models_turns_a_refusal_into_a_warning() {
        let report = check(&["gpt-4.5-preview".to_string()], TODAY, true);
        assert!(report.refused.is_empty());
        assert!(report.warnings[0].contains("running anyway"));
    }

    #[test]
    fn deprecated_and_legacy_models_warn_once_each() {
        let report = check(&["gpt-4o".to_string(), "o3".to_string()], TODAY, false);
        assert!(report.refused.is_empty());
        let default = crate::args::DEFAULT_MODEL;
        assert_eq!(
            report.warnings,
            [
                format!("model gpt-4o is legacy; consider {default}"),
                format!("model o3 is deprecated (retires 2026-12-11); consider {default}"),
            ]
        );
    }

    #[test]
    fn current_and_unknown_models_pass_silently() {
        let report = check(
            &["gpt-5.6-luna".to_string(), "acme-internal-llm".to_string()],
            TODAY,
            false,
        );
        assert_eq!(report, GateReport::default());
    }

    #[test]
    fn a_deprecation_past_its_date_is_refused() {
        assert!(check(&["gpt-4".to_string()], TODAY, false)
            .refused
            .is_empty());
        assert_eq!(
            check(&["gpt-4".to_string()], "2026-10-23", false)
                .refused
                .len(),
            1
        );
    }

    #[test]
    fn enforce_fails_on_a_retired_role_and_passes_otherwise() {
        let data = json!({"models": {"verify": {"id": "claude-2.0"}}});
        let err = enforce_on("gpt-5.6-luna", &data, false, TODAY).unwrap_err();
        assert!(err.contains("claude-2.0 is retired"), "{err}");
        assert_eq!(enforce_on("gpt-5.6-luna", &data, true, TODAY), Ok(()));
        assert_eq!(enforce_on("gpt-4o", &Value::Null, false, TODAY), Ok(()));
        assert_eq!(enforce("gpt-5.6-luna", &Value::Null, false), Ok(()));
    }

    #[test]
    fn capability_rows_name_each_model() {
        let rendered =
            render_capabilities(&["gpt-5.6-luna".to_string(), "acme".to_string()], TODAY);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("  [model] gpt-5.6-luna: family=gpt-5.6-luna"));
        assert!(lines[0].contains("lifecycle=current"));
        assert!(lines[1].contains("acme: family=(unknown"));
    }
}
