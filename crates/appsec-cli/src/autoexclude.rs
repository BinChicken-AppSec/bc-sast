use std::path::{Path, PathBuf};
use std::sync::Arc;

use appsec_llm_client::LlmClient;
use appsec_orchestrator::ScanConfig;
use appsec_stage_s1::{AutoExcludeConfig, AutoExcludeDiagnostics, AutoExcludeOverlay};

use crate::{config_overrides, Cli};

fn resolve_enabled(cli: &Cli, config_data: Option<&serde_json::Value>) -> bool {
    if cli.no_auto_step1 {
        return false;
    }
    if cli.auto_step1 {
        return true;
    }
    config_data
        .and_then(|d| d.get("step1"))
        .and_then(|s| s.get("auto_exclude"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn overlay_path(repo_root: &Path) -> Option<PathBuf> {
    let db_path = appsec_checkpoint::default_db_path().ok()?;
    let state_dir = db_path.parent()?;
    let run_id = appsec_checkpoint::run_id_for(repo_root);
    Some(
        state_dir
            .join("checkpoints")
            .join(run_id)
            .join("step1.yaml"),
    )
}

fn apply_overlay(config: &mut ScanConfig, overlay: &AutoExcludeOverlay) {
    config
        .step1
        .walk
        .exclude_dirs
        .extend(overlay.exclude_dirs.iter().cloned());
    config
        .step1
        .walk
        .exclude_exts
        .extend(overlay.exclude_exts.iter().cloned());
    config
        .step1
        .walk
        .exclude_globs
        .extend(overlay.exclude_globs.iter().cloned());
    if let Some(kb) = overlay.max_file_kb {
        config.step1.walk.max_file_kb = kb;
    }
    let dd = &overlay.config_dedup;
    if let Some(v) = dd.get("enabled").and_then(serde_json::Value::as_bool) {
        config.step1.dedup.enabled = v;
    }
    if let Some(exts) = dd.get("exts").and_then(serde_json::Value::as_array) {
        config.step1.dedup.exts = exts
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect();
    }
    if let Some(v) = dd
        .get("min_cluster_size")
        .and_then(serde_json::Value::as_u64)
    {
        config.step1.dedup.min_cluster_size = v as usize;
    }
    if let Some(v) = dd
        .get("keep_per_top_dir")
        .and_then(serde_json::Value::as_bool)
    {
        config.step1.dedup.keep_per_top_dir = v;
    }
    if let Some(v) = dd
        .get("promote_on_secret_hit")
        .and_then(serde_json::Value::as_bool)
    {
        config.step1.dedup.promote_on_secret_hit = v;
    }
    if let Some(v) = dd
        .get("promote_on_insecure_value")
        .and_then(serde_json::Value::as_bool)
    {
        config.step1.dedup.promote_on_insecure_value = v;
    }
    if let Some(v) = dd.get("max_file_kb").and_then(serde_json::Value::as_u64) {
        config.step1.dedup.max_file_kb = v;
    }
}

pub async fn maybe_apply(
    cli: &Cli,
    llm: &Arc<dyn LlmClient>,
    repo_root: &Path,
    config: &mut ScanConfig,
) {
    let config_data = match cli
        .config
        .as_deref()
        .map(crate::config_load::load)
        .transpose()
    {
        Ok(loaded) => loaded.map(|loaded| loaded.data),
        Err(e) => {
            tracing::warn!("[auto-step1] --config did not load ({e}); skipping the survey");
            return;
        }
    };

    if !resolve_enabled(cli, config_data.as_ref()) {
        return;
    }

    let Some(path) = overlay_path(repo_root) else {
        tracing::warn!("[auto-step1] state dir unavailable; continuing with global step1 only");
        return;
    };

    let (overlay, diagnostics) = if cli.resume && path.is_file() {
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                tracing::info!("[auto-step1] reusing {}", path.display());
                (Some(AutoExcludeOverlay::from_yaml(&text)), None)
            }
            Err(e) => {
                tracing::warn!(
                    "[auto-step1] failed to read {} ({e}); re-surveying",
                    path.display()
                );
                surveyed(run_and_write(llm, repo_root, config_data.as_ref(), &path, config).await)
            }
        }
    } else {
        surveyed(run_and_write(llm, repo_root, config_data.as_ref(), &path, config).await)
    };

    let Some(overlay) = overlay else { return };
    if let Some(diag) = &diagnostics {
        config.autoexclude = appsec_orchestrator::autoexclude_counts(diag);
    }
    let dirs = overlay.exclude_dirs.len();
    let exts = overlay.exclude_exts.len();
    let globs = overlay.exclude_globs.len();
    apply_overlay(config, &overlay);
    tracing::info!("[auto-step1] applied overlay  (exclude_dirs={dirs} exts={exts} globs={globs})");
}

fn surveyed(
    result: Option<(AutoExcludeOverlay, AutoExcludeDiagnostics)>,
) -> (Option<AutoExcludeOverlay>, Option<AutoExcludeDiagnostics>) {
    match result {
        Some((overlay, diag)) => (Some(overlay), Some(diag)),
        None => (None, None),
    }
}

async fn run_and_write(
    llm: &Arc<dyn LlmClient>,
    repo_root: &Path,
    config_data: Option<&serde_json::Value>,
    path: &Path,
    config: &ScanConfig,
) -> Option<(AutoExcludeOverlay, AutoExcludeDiagnostics)> {
    let role = config_data
        .map(|d| config_overrides::model_role(d, "autoexclude"))
        .unwrap_or_default();
    let model = role
        .id
        .clone()
        .unwrap_or_else(|| config.step1.model.clone());
    let max_tokens = config_data
        .and_then(|d| d.get("step1"))
        .and_then(|s| s.get("auto_exclude_max_tokens"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(8000) as u32;

    let ae_config = AutoExcludeConfig {
        model,
        max_tokens,
        max_transient_retries: config.step1.max_transient_retries,
        retry_backoff_base: config.step1.retry_backoff_base,
        temperature: role.temperature.or(config.step1.temperature),
        top_p: role.top_p.or(config.step1.top_p),
        seed: role.seed.or(config.step1.seed),
        reasoning_effort: role.effort.or(config.step1.reasoning_effort),
        openai_api: role.openai_api().or(config.step1.openai_api),
        timeout_secs: config.step1.timeout_secs,
    };

    tracing::info!("[auto-step1] surveying {}", repo_root.display());
    let result = appsec_stage_s1::run_autoexclude_with_diagnostics(
        llm.as_ref(),
        repo_root,
        &config.step1.walk,
        &config.step1.dedup.exts,
        config.step1.dedup.min_cluster_size,
        &ae_config,
    )
    .await;

    match result {
        Ok((overlay, diag)) => {
            if let Some(parent) = path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    tracing::warn!(
                        "[auto-step1] failed to create {} ({e}); continuing with global step1 only",
                        parent.display()
                    );
                    return Some((overlay, diag));
                }
            }
            if let Err(e) = std::fs::write(path, overlay.to_yaml()) {
                tracing::warn!("[auto-step1] failed to write {} ({e})", path.display());
            }
            Some((overlay, diag))
        }
        Err(e) => {
            tracing::warn!("[auto-step1] failed ({e}); continuing with global step1 only");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(auto: bool, no_auto: bool) -> Cli {
        let mut c = crate::test_support::minimal_cli(Path::new("/tmp/repo"));
        c.auto_step1 = auto;
        c.no_auto_step1 = no_auto;
        c
    }

    #[test]
    fn resolve_enabled_no_auto_step1_wins_over_everything() {
        let c = cli(true, true);
        let cfg = serde_json::json!({"step1": {"auto_exclude": true}});
        assert!(!resolve_enabled(&c, Some(&cfg)));
    }

    #[test]
    fn resolve_enabled_auto_step1_flag_turns_it_on() {
        assert!(resolve_enabled(&cli(true, false), None));
    }

    #[test]
    fn resolve_enabled_config_key_turns_it_on_when_truthy() {
        let cfg = serde_json::json!({"step1": {"auto_exclude": true}});
        assert!(resolve_enabled(&cli(false, false), Some(&cfg)));
    }

    #[test]
    fn resolve_enabled_off_by_default() {
        assert!(!resolve_enabled(&cli(false, false), None));
        let cfg = serde_json::json!({"step1": {"auto_exclude": false}});
        assert!(!resolve_enabled(&cli(false, false), Some(&cfg)));
    }

    #[tokio::test]
    async fn overlay_path_lives_under_state_dir_checkpoints_run_id() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", dir.path());
        }
        let path = overlay_path(Path::new("/some/repo")).unwrap();
        crate::tests::restore_env("BC_STATE_DIR", prior);
        assert!(path.starts_with(dir.path().join("checkpoints")));
        assert_eq!(path.file_name().unwrap(), "step1.yaml");
    }

    #[test]
    fn apply_overlay_appends_lists_and_replaces_scalars() {
        let mut config = crate::tests::fast_config();
        config.step1.walk.exclude_dirs.push("existing".to_string());
        let overlay = AutoExcludeOverlay {
            exclude_dirs: vec!["generated".to_string()],
            exclude_exts: vec![".pb.go".to_string()],
            exclude_globs: vec!["tools/**".to_string()],
            max_file_kb: Some(2048),
            config_dedup: std::collections::BTreeMap::from([
                (
                    "min_cluster_size".to_string(),
                    serde_json::Value::from(9u64),
                ),
                ("enabled".to_string(), serde_json::Value::Bool(false)),
            ]),
        };
        apply_overlay(&mut config, &overlay);
        assert_eq!(
            config.step1.walk.exclude_dirs,
            vec!["existing".to_string(), "generated".to_string()]
        );
        assert_eq!(config.step1.walk.exclude_exts, vec![".pb.go".to_string()]);
        assert_eq!(config.step1.walk.max_file_kb, 2048);
        assert_eq!(config.step1.dedup.min_cluster_size, 9);
        assert!(!config.step1.dedup.enabled);
    }

    #[test]
    fn apply_overlay_config_dedup_remaining_keys() {
        let mut config = crate::tests::fast_config();
        let overlay = AutoExcludeOverlay {
            config_dedup: std::collections::BTreeMap::from([
                ("exts".to_string(), serde_json::json!([".tfvars", ".cue"])),
                (
                    "keep_per_top_dir".to_string(),
                    serde_json::Value::Bool(true),
                ),
                (
                    "promote_on_secret_hit".to_string(),
                    serde_json::Value::Bool(true),
                ),
                (
                    "promote_on_insecure_value".to_string(),
                    serde_json::Value::Bool(true),
                ),
                ("max_file_kb".to_string(), serde_json::Value::from(512u64)),
            ]),
            ..Default::default()
        };
        apply_overlay(&mut config, &overlay);
        assert_eq!(
            config.step1.dedup.exts,
            vec![".tfvars".to_string(), ".cue".to_string()]
        );
        assert!(config.step1.dedup.keep_per_top_dir);
        assert!(config.step1.dedup.promote_on_secret_hit);
        assert!(config.step1.dedup.promote_on_insecure_value);
        assert_eq!(config.step1.dedup.max_file_kb, 512);
    }

    struct FailingLlmClient;
    #[async_trait::async_trait]
    impl LlmClient for FailingLlmClient {
        async fn chat(
            &self,
            _request: &appsec_llm_client::ChatRequest,
        ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
            Err(appsec_llm_client::LlmError::InvalidRequest {
                message: "should never be called".to_string(),
            })
        }
    }

    struct FakeLlmClient {
        yaml: &'static str,
    }
    #[async_trait::async_trait]
    impl LlmClient for FakeLlmClient {
        async fn chat(
            &self,
            _request: &appsec_llm_client::ChatRequest,
        ) -> Result<appsec_llm_client::ChatResponse, appsec_llm_client::LlmError> {
            Ok(appsec_llm_client::ChatResponse {
                content: vec![appsec_llm_client::ContentBlock::text(self.yaml)],
                stop_reason: appsec_llm_client::StopReason::EndTurn,
                usage: appsec_llm_client::Usage::default(),
            })
        }
    }

    #[tokio::test]
    async fn maybe_apply_is_a_no_op_when_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let c = cli(false, false);
        let llm: Arc<dyn LlmClient> = Arc::new(FailingLlmClient);
        let mut config = crate::tests::fast_config();
        let before = config.step1.walk.exclude_dirs.clone();
        maybe_apply(&c, &llm, dir.path(), &mut config).await;
        assert_eq!(config.step1.walk.exclude_dirs, before);
    }

    #[tokio::test]
    async fn maybe_apply_surveys_calls_the_model_and_applies_the_overlay_when_enabled() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }

        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("main.rs"), "fn main() {}").unwrap();

        let c = cli(true, false);
        let llm: Arc<dyn LlmClient> = Arc::new(FakeLlmClient {
            yaml: "```yaml\nexclude_dirs:\n  - generated\n```",
        });
        let mut config = crate::tests::fast_config();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        let path = overlay_path(repo.path()).unwrap();
        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert!(config
            .step1
            .walk
            .exclude_dirs
            .contains(&"generated".to_string()));
        assert!(config.autoexclude.ran);
        assert_eq!(config.autoexclude.files_before, 1);
        assert!(
            path.is_file(),
            "overlay file should have been written to {}",
            path.display()
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("generated"));
    }

    #[tokio::test]
    async fn maybe_apply_degrades_without_touching_config_when_the_llm_call_fails() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }

        let repo = tempfile::tempdir().unwrap();
        let c = cli(true, false);
        let llm: Arc<dyn LlmClient> = Arc::new(FailingLlmClient);
        let mut config = crate::tests::fast_config();
        let before = config.step1.walk.exclude_dirs.clone();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert_eq!(config.step1.walk.exclude_dirs, before);
    }

    #[tokio::test]
    async fn maybe_apply_reuses_a_previously_written_overlay_on_resume() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }

        let repo = tempfile::tempdir().unwrap();
        let path = overlay_path(repo.path()).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            AutoExcludeOverlay {
                exclude_dirs: vec!["from-resume".to_string()],
                ..Default::default()
            }
            .to_yaml(),
        )
        .unwrap();

        let mut c = cli(true, false);
        c.resume = true;
        let llm: Arc<dyn LlmClient> = Arc::new(FailingLlmClient);
        let mut config = crate::tests::fast_config();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert!(config
            .step1
            .walk
            .exclude_dirs
            .contains(&"from-resume".to_string()));
        assert!(!config.autoexclude.ran);
    }

    #[tokio::test]
    async fn maybe_apply_warns_and_returns_when_the_state_dir_is_unavailable() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", &blocker);
        }

        let repo = tempfile::tempdir().unwrap();
        let c = cli(true, false);
        let llm: Arc<dyn LlmClient> = Arc::new(FailingLlmClient);
        let mut config = crate::tests::fast_config();
        let before = config.step1.walk.exclude_dirs.clone();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert_eq!(config.step1.walk.exclude_dirs, before);
    }

    #[tokio::test]
    async fn maybe_apply_resurveys_when_the_resume_overlay_cannot_be_read() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }

        let repo = tempfile::tempdir().unwrap();
        let path = overlay_path(repo.path()).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut unreadable = b"exclude_dirs:\n  - stale\n".to_vec();
        unreadable.extend_from_slice(&[0xff, 0xfe]);
        std::fs::write(&path, unreadable).unwrap();

        let mut c = cli(true, false);
        c.resume = true;
        let llm: Arc<dyn LlmClient> = Arc::new(FakeLlmClient {
            yaml: "```yaml\nexclude_dirs:\n  - resurveyed\n```",
        });
        let mut config = crate::tests::fast_config();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert!(config
            .step1
            .walk
            .exclude_dirs
            .contains(&"resurveyed".to_string()));
        assert!(!config
            .step1
            .walk
            .exclude_dirs
            .contains(&"stale".to_string()));
    }

    #[tokio::test]
    async fn run_and_write_warns_and_still_returns_the_overlay_when_the_checkpoint_dir_cannot_be_created(
    ) {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }

        let repo = tempfile::tempdir().unwrap();
        let path = overlay_path(repo.path()).unwrap();
        let parent = path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(parent.parent().unwrap()).unwrap();
        std::fs::write(&parent, b"not a directory").unwrap();

        let c = cli(true, false);
        let llm: Arc<dyn LlmClient> = Arc::new(FakeLlmClient {
            yaml: "```yaml\nexclude_dirs:\n  - generated\n```",
        });
        let mut config = crate::tests::fast_config();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert!(config
            .step1
            .walk
            .exclude_dirs
            .contains(&"generated".to_string()));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn run_and_write_warns_when_the_overlay_file_cannot_be_written() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }

        let repo = tempfile::tempdir().unwrap();
        let path = overlay_path(repo.path()).unwrap();
        std::fs::create_dir_all(&path).unwrap();

        let c = cli(true, false);
        let llm: Arc<dyn LlmClient> = Arc::new(FakeLlmClient {
            yaml: "```yaml\nexclude_dirs:\n  - generated\n```",
        });
        let mut config = crate::tests::fast_config();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert!(config
            .step1
            .walk
            .exclude_dirs
            .contains(&"generated".to_string()));
        assert!(
            path.is_dir(),
            "the directory should have been left untouched"
        );
    }

    #[tokio::test]
    async fn maybe_apply_loads_the_autoexclude_model_role_from_a_config_file() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }

        let repo = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "step1:\n  auto_exclude: true\n  model: fallback-model\nmodels:\n  autoexclude:\n    id: from-config-model\n",
        )
        .unwrap();

        let mut c = cli(false, false);
        c.config = Some(config_path);
        let llm: Arc<dyn LlmClient> = Arc::new(FakeLlmClient {
            yaml: "```yaml\nexclude_dirs:\n  - generated\n```",
        });
        let mut config = crate::tests::fast_config();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert!(config
            .step1
            .walk
            .exclude_dirs
            .contains(&"generated".to_string()));
    }

    #[tokio::test]
    async fn maybe_apply_skips_the_survey_when_the_config_is_refused_by_policy() {
        let _guard = crate::tests::ENV_LOCK.lock().await;
        let state_dir = tempfile::tempdir().unwrap();
        let prior = std::env::var("BC_STATE_DIR").ok();
        unsafe {
            std::env::set_var("BC_STATE_DIR", state_dir.path());
        }

        let repo = tempfile::tempdir().unwrap();
        std::fs::write(repo.path().join("main.rs"), "fn main() {}").unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "step_remediate:\n  verify_command: make T=${GITHUB_TOKEN}\n",
        )
        .unwrap();

        let mut c = cli(true, false);
        c.config = Some(config_path);
        let llm: Arc<dyn LlmClient> = Arc::new(FakeLlmClient {
            yaml: "```yaml\nexclude_dirs:\n  - generated\n```",
        });
        let mut config = crate::tests::fast_config();
        let before = config.step1.walk.exclude_dirs.clone();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;
        let overlay_written = overlay_path(repo.path()).is_some_and(|p| p.exists());

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert_eq!(config.step1.walk.exclude_dirs, before);
        assert!(!overlay_written);
    }
}
