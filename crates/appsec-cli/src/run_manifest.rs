use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use appsec_llm_client::OpenAiApi;
use appsec_orchestrator::manifest::{
    compose, InputHash, ManifestTarget, ModelEntry, RunFacts, StageTelemetry,
};
use appsec_orchestrator::ScanConfig;
use sha2::{Digest, Sha256};

use crate::{config_load, Cli, Dialect, RemediateSettings};

pub(crate) const DEFAULT_FILE_NAME: &str = "run_manifest.json";

pub(crate) struct ManifestStart {
    path: PathBuf,
    started_at: String,
    started: Instant,
    facts: RunFacts,
}

pub(crate) fn manifest_path(cli: &Cli) -> PathBuf {
    cli.out_run_manifest.clone().unwrap_or_else(|| {
        cli.out_dir
            .clone()
            .unwrap_or_else(|| crate::repo_path(cli).join(crate::DEFAULT_OUT_DIR))
            .join(DEFAULT_FILE_NAME)
    })
}

pub(crate) fn sha256_file(path: &Path) -> Option<String> {
    let hashed = std::fs::File::open(path).and_then(|mut file| {
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>())
    });
    match hashed {
        Ok(hex) => Some(hex),
        Err(e) => {
            eprintln!(
                "  [manifest] could not hash {}: {e}",
                appsec_redact::redact(&path.display().to_string())
            );
            None
        }
    }
}

pub(crate) fn gateway_host(base_url: &str) -> Option<String> {
    reqwest::Url::parse(base_url)
        .ok()?
        .host_str()
        .map(str::to_string)
}

fn dialect_name(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Openai => "openai",
        Dialect::Anthropic => "anthropic",
    }
}

pub(crate) fn models(
    cli: &Cli,
    config: &ScanConfig,
    remediate: Option<&RemediateSettings>,
    client_api: OpenAiApi,
) -> BTreeMap<String, ModelEntry> {
    let anthropic = cli.dialect == Dialect::Anthropic;
    let entry = |id: &str, pin: Option<OpenAiApi>| ModelEntry {
        id: id.to_string(),
        dialect: dialect_name(cli.dialect).to_string(),
        gateway_host: gateway_host(&cli.gateway_base_url),
        pricing_provider: config.pricing.provider.clone(),
        transport: Some(
            crate::llm_settings::transport_label(anthropic, client_api, pin).to_string(),
        ),
        transport_resolved: None,
        fell_back: None,
    };
    let mut roles: Vec<(&str, &str, Option<OpenAiApi>)> = Vec::new();
    if config.step0_enabled {
        if let Some(llm) = &config.step0.llm {
            roles.push(("graph_annotate", &llm.model, llm.openai_api));
        }
    }
    roles.push(("preprocess", &config.step1.model, config.step1.openai_api));
    if config.step2_enabled {
        roles.push(("threatmodel", &config.step2.model, config.step2.openai_api));
    }
    roles.push(("decompose", &config.step3.model, config.step3.openai_api));
    roles.push(("deepdive", &config.step4.model, config.step4.openai_api));
    roles.push(("verify", &config.step6.model, config.step6.openai_api));
    roles.push(("dedup", &config.step7.model, config.step7.openai_api));
    roles.push(("chain", &config.step8.model, config.step8.openai_api));
    if let Some(settings) = remediate {
        let step10 = &settings.config.step10;
        roles.push(("remediate", &step10.model, step10.openai_api));
        if settings.validate_enabled {
            let step11 = &settings.step11;
            roles.push(("validate", &step11.model, step11.openai_api));
        }
    }
    roles
        .into_iter()
        .map(|(role, id, pin)| (role.to_string(), entry(id, pin)))
        .collect()
}

fn input_hashes(cli: &Cli) -> BTreeMap<String, InputHash> {
    let inputs = [
        (
            "cmdb_csv",
            crate::non_empty(&cli.cmdb_csv).map(PathBuf::from),
        ),
        ("remediation_policy", cli.remediation_policy.clone()),
        ("remediation_playbook", cli.remediation_playbook.clone()),
    ];
    inputs
        .into_iter()
        .filter_map(|(name, path)| {
            let path = path?;
            Some((
                name.to_string(),
                InputHash {
                    path: path.display().to_string(),
                    sha256: sha256_file(&path),
                },
            ))
        })
        .collect()
}

pub(crate) fn begin(
    cli: &Cli,
    config: &ScanConfig,
    remediate: Option<&RemediateSettings>,
    client_api: OpenAiApi,
    repo_name: &str,
    argv: Vec<String>,
) -> ManifestStart {
    let loaded = cli
        .config
        .as_ref()
        .and_then(|path| config_load::load(path).ok());
    let overlay_sha256 = loaded.as_ref().and_then(|l| match &l.local_overlay {
        appsec_config::LocalOverlayStatus::Applied { path, .. } => sha256_file(path),
        _ => None,
    });
    ManifestStart {
        path: manifest_path(cli),
        started_at: appsec_metrics::now_iso(),
        started: Instant::now(),
        facts: RunFacts {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            argv,
            config_path: cli.config.as_ref().map(|p| p.display().to_string()),
            config_sha256: cli.config.as_deref().and_then(sha256_file),
            local_overlay_sha256: overlay_sha256,
            input_hashes: input_hashes(cli),
            target: ManifestTarget {
                repo_name: Some(repo_name.to_string()),
                git_sha: None,
            },
            models: models(cli, config, remediate, client_api),
            ..RunFacts::default()
        },
    }
}

pub(crate) fn apply_resolved_transports(
    models: &mut BTreeMap<String, ModelEntry>,
    resolved: impl Fn(&str) -> Option<(&'static str, bool)>,
) {
    for entry in models.values_mut() {
        if let Some((endpoint, fell_back)) = resolved(&entry.id) {
            entry.transport_resolved = Some(endpoint.to_string());
            entry.fell_back = Some(fell_back);
        }
    }
}

pub(crate) fn finish(
    start: ManifestStart,
    telemetry: &StageTelemetry,
    exit_code: i32,
    git_sha: Option<String>,
    responses_fallbacks: Option<u64>,
    resolved_transport: impl Fn(&str) -> Option<(&'static str, bool)>,
) -> Option<PathBuf> {
    let mut facts = start.facts;
    apply_resolved_transports(&mut facts.models, resolved_transport);
    facts.started_at = start.started_at;
    facts.finished_at = appsec_metrics::now_iso();
    facts.duration_sec = (start.started.elapsed().as_secs_f64() * 10.0).round() / 10.0;
    facts.exit_code = exit_code;
    facts.canceled = exit_code == i32::from(crate::cancel::CANCELED_EXIT_CODE);
    facts.target.git_sha = git_sha;
    let mut manifest = compose(facts, telemetry);
    if let Some(n) = responses_fallbacks {
        manifest
            .counters
            .insert("responses_fallbacks".to_string(), n);
    }
    let json = manifest.to_json();
    let written = start
        .path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&start.path, json));
    match written {
        Ok(()) => {
            eprintln!("  [manifest] wrote {}", start.path.display());
            Some(start.path)
        }
        Err(e) => {
            eprintln!(
                "  [manifest] WARNING: failed to write run manifest {}: {e}",
                start.path.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::minimal_cli;

    fn model_entry(id: &str, transport: &str) -> ModelEntry {
        ModelEntry {
            id: id.to_string(),
            dialect: "openai".to_string(),
            gateway_host: None,
            pricing_provider: None,
            transport: Some(transport.to_string()),
            transport_resolved: None,
            fell_back: None,
        }
    }

    #[test]
    fn resolved_transports_are_recorded_per_model_not_per_run() {
        let mut models = BTreeMap::from([
            ("deepdive".to_string(), model_entry("gpt-6-luna", "auto")),
            ("dedup".to_string(), model_entry("gpt-4o", "auto")),
        ]);
        apply_resolved_transports(&mut models, |id| match id {
            "gpt-6-luna" => Some(("responses", false)),
            "gpt-4o" => Some(("chat", true)),
            _ => None,
        });
        let deepdive = &models["deepdive"];
        assert_eq!(deepdive.transport.as_deref(), Some("auto"));
        assert_eq!(deepdive.transport_resolved.as_deref(), Some("responses"));
        assert_eq!(deepdive.fell_back, Some(false));
        let dedup = &models["dedup"];
        assert_eq!(dedup.transport.as_deref(), Some("auto"));
        assert_eq!(dedup.transport_resolved.as_deref(), Some("chat"));
        assert_eq!(dedup.fell_back, Some(true), "reached chat by rejection");
    }

    #[test]
    fn a_pinned_transport_is_still_recorded_as_observed() {
        let mut models =
            BTreeMap::from([("verify".to_string(), model_entry("gpt-6-luna", "responses"))]);
        apply_resolved_transports(&mut models, |_| Some(("responses", false)));
        assert_eq!(
            models["verify"].transport_resolved.as_deref(),
            Some("responses")
        );
    }

    #[test]
    fn a_dialect_with_nothing_to_resolve_leaves_the_fields_unset() {
        let mut models = BTreeMap::from([(
            "verify".to_string(),
            model_entry("claude-opus-5", "messages"),
        )]);
        apply_resolved_transports(&mut models, |_| None);
        assert_eq!(models["verify"].transport.as_deref(), Some("messages"));
        assert_eq!(models["verify"].transport_resolved, None);
        assert_eq!(models["verify"].fell_back, None);
    }

    #[test]
    fn sha256_matches_the_known_vector_and_fails_to_none() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("abc.txt");
        std::fs::write(&file, "abc").unwrap();
        assert_eq!(
            sha256_file(&file).as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(sha256_file(&dir.path().join("missing")), None);
        assert_eq!(sha256_file(dir.path()), None);
    }

    #[test]
    fn sha256_streams_a_file_larger_than_one_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("big");
        std::fs::write(&file, vec![b'a'; 200_000]).unwrap();
        let hex = sha256_file(&file).unwrap();
        assert_eq!(hex.len(), 64);
        let mut hasher = Sha256::new();
        hasher.update(vec![b'a'; 200_000]);
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn gateway_host_keeps_only_the_host() {
        assert_eq!(
            gateway_host("https://user:tok@gw.example.com:8443/v1/tenant-42?key=abc").as_deref(),
            Some("gw.example.com")
        );
        assert_eq!(gateway_host("not a url"), None);
        assert_eq!(gateway_host("unix:/run/socket"), None);
    }

    #[test]
    fn the_manifest_path_defaults_into_the_out_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = minimal_cli(dir.path());
        assert_eq!(
            manifest_path(&cli),
            dir.path().join("security-scan").join(DEFAULT_FILE_NAME)
        );
        cli.out_dir = Some(dir.path().join("out"));
        assert_eq!(
            manifest_path(&cli),
            dir.path().join("out").join(DEFAULT_FILE_NAME)
        );
        cli.out_run_manifest = Some(dir.path().join("m.json"));
        assert_eq!(manifest_path(&cli), dir.path().join("m.json"));
    }

    #[test]
    fn models_names_every_enabled_role_and_skips_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = minimal_cli(dir.path());
        cli.dialect = Dialect::Anthropic;
        cli.gateway_base_url = "https://api.anthropic.com/v1".to_string();
        let mut config = crate::tests::fast_config();
        config.step2_enabled = false;
        config.step0_enabled = true;
        config.pricing.provider = Some("anthropic".to_string());
        let models = models(&cli, &config, None, OpenAiApi::Auto);
        let roles: Vec<&str> = models.keys().map(String::as_str).collect();
        assert_eq!(
            roles,
            [
                "chain",
                "decompose",
                "dedup",
                "deepdive",
                "preprocess",
                "verify"
            ]
        );
        let deepdive = &models["deepdive"];
        assert_eq!(deepdive.dialect, "anthropic");
        assert_eq!(deepdive.gateway_host.as_deref(), Some("api.anthropic.com"));
        assert_eq!(deepdive.pricing_provider.as_deref(), Some("anthropic"));
        assert_eq!(deepdive.transport.as_deref(), Some("messages"));
        assert_eq!(dialect_name(Dialect::Openai), "openai");
    }

    #[test]
    fn each_role_reports_its_own_transport_pin_or_the_clients() {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = minimal_cli(dir.path());
        cli.remediate = true;
        let mut config = crate::tests::fast_config();
        config.step0_enabled = true;
        let mut annotator = appsec_stage_s0::Step0LlmConfig::new("annotator");
        annotator.openai_api = Some(OpenAiApi::Chat);
        config.step0.llm = Some(annotator);
        config.step4.openai_api = Some(OpenAiApi::Responses);
        let mut settings = crate::build_remediate_settings(&cli).unwrap();
        settings.validate_enabled = true;
        settings.config.step10.openai_api = Some(OpenAiApi::Chat);
        let models = models(&cli, &config, Some(&settings), OpenAiApi::Auto);
        let transport = |role: &str| models[role].transport.clone().unwrap();
        assert_eq!(transport("graph_annotate"), "chat");
        assert_eq!(transport("deepdive"), "responses");
        assert_eq!(transport("remediate"), "chat");
        assert_eq!(transport("validate"), "auto");
        assert_eq!(transport("verify"), "auto");
    }

    #[test]
    fn models_include_the_annotator_and_remediation_roles_when_used() {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = minimal_cli(dir.path());
        cli.remediate = true;
        let mut config = crate::tests::fast_config();
        config.step0_enabled = true;
        config.step0.llm = Some(appsec_stage_s0::Step0LlmConfig::new("annotator"));
        let mut settings = crate::build_remediate_settings(&cli).unwrap();
        settings.validate_enabled = true;
        let models = models(&cli, &config, Some(&settings), OpenAiApi::Chat);
        assert_eq!(models["graph_annotate"].id, "annotator");
        assert!(models.contains_key("remediate"));
        assert!(models.contains_key("validate"));
        assert!(models.contains_key("threatmodel"));
    }

    #[test]
    fn input_hashes_cover_the_remaining_file_flags() {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = minimal_cli(dir.path());
        cli.cmdb_csv = dir.path().join("cmdb.csv").display().to_string();
        let hashes = input_hashes(&cli);
        assert_eq!(hashes["cmdb_csv"].sha256, None);
        assert!(!hashes.contains_key("remediation_policy"));
        assert!(
            !hashes.contains_key("cve_file") && !hashes.contains_key("controls_file"),
            "the legacy injection inputs are gone from the manifest"
        );
    }

    #[test]
    fn begin_and_finish_write_a_scrubbed_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "step2:\n  enabled: true\n").unwrap();
        std::fs::write(
            config_dir.path().join("config.local.yaml"),
            "step2:\n  enabled: false\n",
        )
        .unwrap();
        let mut cli = minimal_cli(dir.path());
        cli.config = Some(config_path);
        cli.out_run_manifest = Some(dir.path().join("nested").join("manifest.json"));
        let config = crate::tests::fast_config();
        let start = begin(
            &cli,
            &config,
            None,
            OpenAiApi::Auto,
            "demo",
            vec![
                "appsec-scan".to_string(),
                "--gateway-api-key".to_string(),
                "sk-very-secret".to_string(),
            ],
        );
        let mut telemetry = StageTelemetry::default();
        telemetry.record(&appsec_pipeline_core::ScanEvent::StageStarted {
            stage: "s1-preprocess",
        });
        let path = finish(
            start,
            &telemetry,
            0,
            Some("abc123".to_string()),
            Some(2),
            |_| Some(("responses", false)),
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("sk-very-secret"), "{text}");
        let manifest: appsec_orchestrator::manifest::RunManifest =
            serde_json::from_str(&text).unwrap();
        assert_eq!(manifest.exit_code, 0);
        assert_eq!(manifest.target.git_sha.as_deref(), Some("abc123"));
        assert_eq!(manifest.target.repo_name.as_deref(), Some("demo"));
        assert!(manifest.config_sha256.is_some());
        assert_eq!(manifest.stages.0[0].0, "s1");
        assert!(manifest.models.contains_key("deepdive"));
        assert_eq!(manifest.counters["responses_fallbacks"], 2);
        assert_eq!(
            manifest.models["deepdive"].transport.as_deref(),
            Some("auto")
        );
        let _ = manifest.local_overlay_sha256;
    }

    #[test]
    fn an_unwritable_destination_is_a_warning_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("taken");
        std::fs::create_dir(&target).unwrap();
        let mut cli = minimal_cli(dir.path());
        cli.out_run_manifest = Some(target);
        let start = begin(
            &cli,
            &crate::tests::fast_config(),
            None,
            OpenAiApi::Auto,
            "demo",
            Vec::new(),
        );
        assert_eq!(
            finish(start, &StageTelemetry::default(), 1, None, None, |_| None),
            None
        );
    }
}
