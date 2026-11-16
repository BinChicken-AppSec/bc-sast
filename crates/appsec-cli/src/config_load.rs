use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};

use appsec_config::{ConfigError, LoadedConfig};

static ANNOUNCED: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(Default::default);

pub(crate) fn load(path: &Path) -> Result<LoadedConfig, ConfigError> {
    let loaded = appsec_config::load(path, &crate::getenv)?;
    if let Some(line) = banner_once(&loaded, &ANNOUNCED) {
        eprintln!("  [config] {line}");
    }
    Ok(loaded)
}

fn banner_once(loaded: &LoadedConfig, seen: &Mutex<HashSet<PathBuf>>) -> Option<String> {
    let path = loaded.local_overlay.path()?;
    let line = appsec_config::render_overlay_banner(&loaded.local_overlay, &loaded.data)?;
    let fresh = seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(path.to_path_buf());
    fresh.then(|| appsec_redact::redact(&line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_config::LocalOverlayStatus;

    fn loaded_with(status: LocalOverlayStatus) -> LoadedConfig {
        LoadedConfig {
            data: serde_json::json!({"models": {"deepdive": {"id": "opus"}}}),
            user_provided: serde_json::Value::Null,
            config_dir: PathBuf::from("/c"),
            local_overlay: status,
        }
    }

    #[test]
    fn each_overlay_is_announced_once() {
        let seen = Mutex::default();
        let first = loaded_with(LocalOverlayStatus::Applied {
            path: PathBuf::from("/c/config.local.yaml"),
            overridden_leaves: vec!["models.deepdive.id".to_string()],
            ownership_verified: true,
        });
        let line = banner_once(&first, &seen).unwrap();
        assert!(line.contains("models.deepdive.id=opus"), "{line}");
        assert_eq!(banner_once(&first, &seen), None);
        let other = loaded_with(LocalOverlayStatus::Skipped {
            path: PathBuf::from("/d/config.local.yaml"),
        });
        assert!(banner_once(&other, &seen).unwrap().contains("SKIPPED"));
    }

    #[test]
    fn no_overlay_announces_nothing() {
        let seen = Mutex::default();
        assert_eq!(
            banner_once(&loaded_with(LocalOverlayStatus::Absent), &seen),
            None
        );
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn load_reads_the_file_and_propagates_a_policy_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1:\n  max_turns: 7\n").unwrap();
        let local = dir.path().join("config.local.yaml");
        std::fs::write(&local, "step1:\n  max_turns: 9\n").unwrap();
        std::fs::set_permissions(&local, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        assert_eq!(load(&path).unwrap().data["step1"]["max_turns"], 9);

        std::fs::write(&path, "step1:\n  model: ${SOME_API_KEY}\n").unwrap();
        std::fs::remove_file(&local).unwrap();
        assert!(matches!(
            load(&path).unwrap_err(),
            ConfigError::SecretInterpolation { .. }
        ));
    }
}
