//! Writes `run_manifest.json`: the I/O half of the run manifest, whose
//! pure half (types, composition, argv scrubbing, redaction) is
//! `bc_orchestrator::manifest`. Ported from the Python original's
//! `manifest.py::capture`.
//!
//! [`begin`] snapshots everything knowable before the scan starts (the
//! command line, config and input-file hashes, model routing); [`finish`]
//! adds the stage telemetry and exit code and writes the file. Both are
//! best-effort in the way Python's are: a file that cannot be hashed is
//! recorded as `null`, and a manifest that cannot be written is a warning,
//! never a failed run.
//!
//! Written only when a scan actually ran, like Python's (which writes
//! nothing when `argparse` rejected the arguments or `--help` printed):
//! `main_impl` calls [`begin`] only once it is past every argument check
//! and utility mode, and [`finish`] once the scan has returned.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use bc_llm_client::OpenAiApi;
use bc_orchestrator::manifest::{
    compose, InputHash, ManifestTarget, ModelEntry, RunFacts, StageTelemetry,
};
use bc_orchestrator::ScanConfig;
use sha2::{Digest, Sha256};

use crate::{config_load, config_overrides, Cli, Dialect, RemediateSettings};

/// The manifest's file name inside the out-dir when `--out-run-manifest`
/// is not given. One fixed name rather than Python's timestamped
/// `run_manifest_<ts>.json` in the working directory: the out-dir is
/// per-repo already (`<repo>/security-scan/`), and a fixed name is one a
/// CI step can upload without globbing.
pub(crate) const DEFAULT_FILE_NAME: &str = "run_manifest.json";

/// What [`begin`] captured, carried across the scan to [`finish`].
pub(crate) struct ManifestStart {
    path: PathBuf,
    started_at: String,
    started: Instant,
    facts: RunFacts,
}

/// Where the manifest goes: `--out-run-manifest`, else
/// `<out-dir>/run_manifest.json`, with the out-dir resolved exactly as
/// `resolve_output_paths` resolves it for the reports.
pub(crate) fn manifest_path(cli: &Cli) -> PathBuf {
    cli.out_run_manifest.clone().unwrap_or_else(|| {
        cli.out_dir
            .clone()
            .unwrap_or_else(|| crate::repo_path(cli).join(crate::DEFAULT_OUT_DIR))
            .join(DEFAULT_FILE_NAME)
    })
}

/// Hex SHA-256 of a file's contents, streamed so a large input costs no
/// memory. `None`, with a warning, when it cannot be read: Python's
/// `_config_sha256` records `None` rather than failing the run.
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
                bc_redact::redact(&path.display().to_string())
            );
            None
        }
    }
}

/// The gateway's host alone: never its scheme, port, path, query or
/// userinfo, any of which can carry a tenant id or a credential. `None`
/// for a URL that does not parse or has no host.
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

/// Every model role this run routes, keyed by Python's role names
/// (`preprocess`, `deepdive`, ...). One dialect and gateway serve every
/// role in this port, so only the model id and the wire API vary:
/// `transport` is the role's `models.<role>.use_responses_api` pin when
/// it has one, else `client_api` (`--openai-api`), and `messages` on the
/// Anthropic dialect. Roles whose stage is switched off are left out:
/// routing that is never used is noise.
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

/// The input files this run read, each hashed: the injected CVE feed and
/// design controls (from the flag, else `--config`'s `inject.*`), the
/// CMDB CSV, and the remediation policy and playbook. Only the ones
/// actually configured appear.
fn input_hashes(cli: &Cli, config_data: &serde_json::Value) -> BTreeMap<String, InputHash> {
    let config_dir = cli
        .config
        .as_ref()
        .and_then(|p| p.parent())
        .unwrap_or(Path::new(""));
    let (config_cves, config_controls) = config_overrides::inject_paths(config_data, config_dir);
    let inputs = [
        ("cve_file", cli.cve_file.clone().or(config_cves)),
        (
            "controls_file",
            cli.controls_file.clone().or(config_controls),
        ),
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

/// Snapshots the run's facts before the scan starts. `argv` is the raw
/// command line; it is scrubbed when the manifest is composed.
/// `client_api` is the OpenAI API shape the client was built with.
pub(crate) fn begin(
    cli: &Cli,
    config: &ScanConfig,
    remediate: Option<&RemediateSettings>,
    client_api: OpenAiApi,
    repo_name: &str,
    argv: Vec<String>,
) -> ManifestStart {
    // A second read of `--config`, like every other consumer's in this
    // crate; `build_scan_config` already failed the run on a bad one.
    let loaded = cli
        .config
        .as_ref()
        .and_then(|path| config_load::load(path).ok());
    let overlay_sha256 = loaded.as_ref().and_then(|l| match &l.local_overlay {
        bc_config::LocalOverlayStatus::Applied { path, .. } => sha256_file(path),
        _ => None,
    });
    let config_data = loaded.map(|l| l.data).unwrap_or_default();
    ManifestStart {
        path: manifest_path(cli),
        started_at: bc_metrics::now_iso(),
        started: Instant::now(),
        facts: RunFacts {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            argv,
            config_path: cli.config.as_ref().map(|p| p.display().to_string()),
            config_sha256: cli.config.as_deref().and_then(sha256_file),
            local_overlay_sha256: overlay_sha256,
            input_hashes: input_hashes(cli, &config_data),
            target: ManifestTarget {
                repo_name: Some(repo_name.to_string()),
                git_sha: None,
            },
            models: models(cli, config, remediate, client_api),
            ..RunFacts::default()
        },
    }
}

/// Composes and writes the manifest. `git_sha` is the scanned commit,
/// when known. `responses_fallbacks` is how many models the OpenAI
/// client moved from the Responses API to Chat Completions this run
/// (`LearnedModels::responses_fallbacks`), recorded as a counter; `None`
/// on the Anthropic dialect, which has no such choice to report. Returns
/// the path written, or `None` (after a warning on stderr) when it could
/// not be.
pub(crate) fn finish(
    start: ManifestStart,
    telemetry: &StageTelemetry,
    exit_code: i32,
    git_sha: Option<String>,
    responses_fallbacks: Option<u64>,
) -> Option<PathBuf> {
    let mut facts = start.facts;
    facts.started_at = start.started_at;
    facts.finished_at = bc_metrics::now_iso();
    facts.duration_sec = (start.started.elapsed().as_secs_f64() * 10.0).round() / 10.0;
    facts.exit_code = exit_code;
    // 130 is only ever a cancellation (see `crate::process_exit_code`).
    facts.canceled = exit_code == i32::from(crate::cancel::CANCELED_EXIT_CODE);
    facts.target.git_sha = git_sha;
    let mut manifest = compose(facts, telemetry);
    if let Some(n) = responses_fallbacks {
        manifest
            .counters
            .insert("responses_fallbacks".to_string(), n);
    }
    let json = manifest.to_json();
    // `create_dir_all("")` (a bare file name's parent) is a no-op.
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

    #[test]
    fn sha256_matches_the_known_vector_and_fails_to_none() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("abc.txt");
        std::fs::write(&file, "abc").unwrap();
        assert_eq!(
            sha256_file(&file).as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        // Missing, and a directory (opens, but cannot be read): both are
        // recorded as unknown, never a failed run.
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
        let mut annotator = bc_stage_s0::Step0LlmConfig::new("annotator");
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
        config.step0.llm = Some(bc_stage_s0::Step0LlmConfig::new("annotator"));
        let mut settings = crate::build_remediate_settings(&cli).unwrap();
        settings.validate_enabled = true;
        let models = models(&cli, &config, Some(&settings), OpenAiApi::Chat);
        assert_eq!(models["graph_annotate"].id, "annotator");
        assert!(models.contains_key("remediate"));
        assert!(models.contains_key("validate"));
        assert!(models.contains_key("threatmodel"));
    }

    #[test]
    fn input_hashes_cover_the_flags_and_the_config_inject_paths() {
        let dir = tempfile::tempdir().unwrap();
        let cves = dir.path().join("cves.json");
        std::fs::write(&cves, "[]").unwrap();
        let mut cli = minimal_cli(dir.path());
        cli.cve_file = Some(cves.clone());
        cli.cmdb_csv = dir.path().join("cmdb.csv").display().to_string();
        cli.config = Some(dir.path().join("cfg").join("config.yaml"));
        let data = serde_json::json!({"inject": {"controls_file": "controls.yaml"}});
        let hashes = input_hashes(&cli, &data);
        assert!(hashes["cve_file"].sha256.is_some());
        // Configured but absent: recorded, with an unknown hash.
        assert_eq!(hashes["cmdb_csv"].sha256, None);
        assert_eq!(
            PathBuf::from(&hashes["controls_file"].path),
            dir.path().join("cfg").join("controls.yaml")
        );
        assert!(!hashes.contains_key("remediation_policy"));
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
                "bc-sast".to_string(),
                "--gateway-api-key".to_string(),
                "sk-very-secret".to_string(),
            ],
        );
        let mut telemetry = StageTelemetry::default();
        telemetry.record(&bc_pipeline_core::ScanEvent::StageStarted {
            stage: "s1-preprocess",
        });
        let path = finish(start, &telemetry, 0, Some("abc123".to_string()), Some(2)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("sk-very-secret"), "{text}");
        let manifest: bc_orchestrator::manifest::RunManifest = serde_json::from_str(&text).unwrap();
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
        // The overlay beside the config is hashed only if it was applied;
        // either way the field is present and never fails the run.
        let _ = manifest.local_overlay_sha256;
    }

    #[test]
    fn an_unwritable_destination_is_a_warning_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should go: the write fails.
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
            finish(start, &StageTelemetry::default(), 1, None, None),
            None
        );
    }
}
