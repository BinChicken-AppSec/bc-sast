//! `--auto-step1`/`step1.auto_exclude` orchestration: resolve whether
//! it's enabled for this run, survey the repo and derive an overlay (or
//! reuse a previously-written one on `--resume`), and apply it onto the
//! already-built [`ScanConfig`]. Ported from `orchestrator/entry.py`'s
//! `_resolve_auto_step1` and `orchestrator/scan.py:155-182`'s own
//! "Optional: AI-derive a per-target step1 overlay" block.
//!
//! Deliberately runs AFTER [`crate::build_scan_config`] rather than
//! reusing `bc_config::apply_step1_overlay` (which merges onto the RAW
//! YAML `Value` tree, before it's converted into a typed [`ScanConfig`]):
//! by the time this crate has a `ScanConfig` to work with, the raw
//! `Value` is already gone, so the parsed [`bc_stage_s1::AutoExcludeOverlay`]
//! is appended directly onto `config.step1.walk`/`.dedup`'s own typed
//! fields instead. `apply_step1_overlay` stays reserved for a future
//! `--step1-config` (an OPERATOR-supplied overlay file, applied earlier,
//! before the raw config is ever converted to typed structs) — a
//! different integration point despite the shared "step1 overlay"
//! vocabulary.
//!
//! Any failure here (LLM call, IO) is caught and logged, never
//! propagated — matching `scan.py`'s own `except Exception: print WARN;
//! continue with global step1 only`, since a broken auto-exclude pass
//! must never abort the scan it was only ever meant to narrow.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bc_llm_client::LlmClient;
use bc_orchestrator::ScanConfig;
use bc_stage_s1::{AutoExcludeConfig, AutoExcludeDiagnostics, AutoExcludeOverlay};

use crate::{config_overrides, Cli};

/// Resolve whether auto-step1 runs for this scan.
///
/// Precedence (highest first): `--no-auto-step1` (hard OFF, wins over
/// everything) > `--auto-step1` (ON) > `step1.auto_exclude` in
/// `--config` (ON when truthy) > OFF. Mirrors `_resolve_auto_step1`
/// exactly, including its OR-precedence with `--remediate`/
/// `step_remediate.enabled`'s own shape.
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

/// `<state-dir>/checkpoints/<run_id>/step1.yaml` — mirrors Python's own
/// `ckpt_dir / "step1.yaml"` naming/location, adapted to this port's
/// single-SQLite-file state layout (`default_db_path()`'s own parent
/// directory stands in for Python's separate per-run checkpoint dir).
fn overlay_path(repo_root: &Path) -> Option<PathBuf> {
    let db_path = bc_checkpoint::default_db_path().ok()?;
    let state_dir = db_path.parent()?;
    let run_id = bc_checkpoint::run_id_for(repo_root);
    Some(
        state_dir
            .join("checkpoints")
            .join(run_id)
            .join("step1.yaml"),
    )
}

/// Applies `overlay` onto `config.step1`'s typed fields: exclusion lists
/// append (already de-duplicated against what's already excluded by
/// [`bc_stage_s1::run_autoexclude`] itself), `max_file_kb`/`config_dedup`
/// entries replace only when the model actually proposed a change.
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

/// Entry point: resolves whether auto-step1 is enabled, and if so,
/// reuses a `--resume`-detected prior overlay or runs a fresh
/// survey+LLM call, then applies the result onto `config` in place.
/// Never returns an error — every failure mode degrades to "no overlay
/// applied, scan proceeds with global step1 only", printed to stderr,
/// exactly matching Python's own non-fatal treatment of this optional
/// pre-pass. That includes a `--config` that fails to load, which skips
/// the survey (and its model call) outright rather than running it as if
/// no config had been given.
pub async fn maybe_apply(
    cli: &Cli,
    llm: &Arc<dyn LlmClient>,
    repo_root: &Path,
    config: &mut ScanConfig,
) {
    // A `--config` that fails to load (including a secret-interpolation or
    // untrusted-overlay refusal) is NOT read as "no config": that would
    // run the survey with this function's own defaults and quietly ignore
    // whatever the operator's file said. Fail closed on this optional
    // pass instead. `build_scan_config` has already failed the whole run
    // on the same file in every real call path, so this only matters for
    // a caller that skipped it.
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
    // Only a survey that actually ran this invocation has guard decisions
    // to report; an overlay reused on `--resume` does not.
    if let Some(diag) = &diagnostics {
        config.autoexclude = bc_orchestrator::autoexclude_counts(diag);
    }
    let dirs = overlay.exclude_dirs.len();
    let exts = overlay.exclude_exts.len();
    let globs = overlay.exclude_globs.len();
    apply_overlay(config, &overlay);
    tracing::info!("[auto-step1] applied overlay  (exclude_dirs={dirs} exts={exts} globs={globs})");
}

/// A fresh survey's result split into the overlay and its guard
/// diagnostics, in the shape [`maybe_apply`] consumes.
fn surveyed(
    result: Option<(AutoExcludeOverlay, AutoExcludeDiagnostics)>,
) -> (Option<AutoExcludeOverlay>, Option<AutoExcludeDiagnostics>) {
    match result {
        Some((overlay, diag)) => (Some(overlay), Some(diag)),
        None => (None, None),
    }
}

/// Runs the survey+LLM call, writes the overlay file on success, and
/// returns the parsed overlay with what the overlay guards decided, or
/// `None` (after a WARN to stderr) on any failure, so [`maybe_apply`] can
/// degrade gracefully.
async fn run_and_write(
    llm: &Arc<dyn LlmClient>,
    repo_root: &Path,
    config_data: Option<&serde_json::Value>,
    path: &Path,
    config: &ScanConfig,
) -> Option<(AutoExcludeOverlay, AutoExcludeDiagnostics)> {
    // `models.autoexclude` — id AND sampling knobs. The survey call is
    // as much an LLM call as any stage's, so it gets the same treatment;
    // without a role of its own it inherits S1's model (Python's own
    // fallback) and S1's already-resolved sampling.
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
    let result = bc_stage_s1::run_autoexclude_with_diagnostics(
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
            _request: &bc_llm_client::ChatRequest,
        ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
            Err(bc_llm_client::LlmError::InvalidRequest {
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
            _request: &bc_llm_client::ChatRequest,
        ) -> Result<bc_llm_client::ChatResponse, bc_llm_client::LlmError> {
            Ok(bc_llm_client::ChatResponse {
                content: vec![bc_llm_client::ContentBlock::text(self.yaml)],
                stop_reason: bc_llm_client::StopReason::EndTurn,
                usage: bc_llm_client::Usage::default(),
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
        // The guards' decisions travel with the config into the scan's
        // Pipeline Diagnostics.
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
        // A FailingLlmClient proves the model is never actually called —
        // the whole point of `--resume` reuse.
        let llm: Arc<dyn LlmClient> = Arc::new(FailingLlmClient);
        let mut config = crate::tests::fast_config();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        assert!(config
            .step1
            .walk
            .exclude_dirs
            .contains(&"from-resume".to_string()));
        // A reused overlay carries no guard decisions of its own.
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
        // The overlay is a regular file whose text cannot be read (it is not
        // UTF-8), which fails `read_to_string` for every user. A chmod 000
        // file would not stop root, which bypasses permission bits.
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
        // Pre-create a plain FILE at the exact spot the checkpoint run
        // directory needs to live, so `create_dir_all(parent)` fails.
        std::fs::write(&parent, b"not a directory").unwrap();

        let c = cli(true, false);
        let llm: Arc<dyn LlmClient> = Arc::new(FakeLlmClient {
            yaml: "```yaml\nexclude_dirs:\n  - generated\n```",
        });
        let mut config = crate::tests::fast_config();
        maybe_apply(&c, &llm, repo.path(), &mut config).await;

        crate::tests::restore_env("BC_STATE_DIR", prior);

        // The overlay must still be applied in-memory even though it
        // couldn't be persisted for a later `--resume`.
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
        // Pre-create the parent as a real directory, then occupy the
        // overlay file's own path with a directory too, so the final
        // `std::fs::write` fails with "Is a directory".
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

        // `--auto-step1` is on and the model would answer, so the only
        // thing that can keep the overlay out is the refused config.
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
