mod banner;
mod env;
mod merge;
mod overlay;
pub mod policy;
mod step_defaults;

use std::fmt;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub use banner::render_overlay_banner;
pub use env::expand;
pub use merge::{append_merge, deep_merge, replace_merge};
pub use overlay::{overlay_trust_verdict, OverlayFacts};
pub use step_defaults::step_defaults;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        message: String,
    },
    Parse {
        path: PathBuf,
        message: String,
    },
    NotAMapping {
        path: PathBuf,
    },
    NetworkPath {
        path: PathBuf,
    },
    ConfigInsideScanTarget {
        config_path: PathBuf,
        scan_target_root: PathBuf,
    },
    SecretInterpolation {
        key_path: String,
        var: String,
    },
    UntrustedOverlay {
        path: PathBuf,
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, message } => write!(f, "{}: {message}", path.display()),
            ConfigError::Parse { path, message } => write!(f, "{}: {message}", path.display()),
            ConfigError::NotAMapping { path } => {
                write!(f, "{}: config must be a YAML mapping", path.display())
            }
            ConfigError::NetworkPath { path } => write!(
                f,
                "refusing network/UNC path {} (reading it could leak credentials over SMB)",
                path.display()
            ),
            ConfigError::ConfigInsideScanTarget { config_path, scan_target_root } => write!(
                f,
                "refusing config {} resolved inside scan target {} (set BC_ALLOW_CWD_CONFIG to override)",
                config_path.display(),
                scan_target_root.display()
            ),
            ConfigError::SecretInterpolation { key_path, var } => write!(
                f,
                "config key '{}' interpolates environment variable '{var}', whose name \
                 matches a secret pattern; secret-named variables may expand only into: {}. \
                 Remedies: pass the credential through its CLI flag or environment binding \
                 instead, rename the variable, or write the value literally",
                display_key_path(key_path),
                policy::describe_destinations(policy::CREDENTIAL_DESTINATIONS)
            ),
            ConfigError::UntrustedOverlay { path, reason } => write!(
                f,
                "config overlay {} is not trusted: {reason}. It must be a regular file \
                 owned by the invoking user (or root) and not group/world-writable: fix it \
                 with `chmod go-w` (and `chown` it to yourself if needed), or set \
                 BC_NO_LOCAL_CONFIG to skip the overlay",
                path.display()
            ),
        }
    }
}

fn display_key_path(key_path: &str) -> &str {
    if key_path.is_empty() {
        "(root)"
    } else {
        key_path
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOverlayStatus {
    Absent,
    Applied {
        path: PathBuf,
        overridden_leaves: Vec<String>,
        ownership_verified: bool,
    },
    Skipped {
        path: PathBuf,
    },
}

impl LocalOverlayStatus {
    pub fn path(&self) -> Option<&Path> {
        match self {
            LocalOverlayStatus::Absent => None,
            LocalOverlayStatus::Applied { path, .. } | LocalOverlayStatus::Skipped { path } => {
                Some(path)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoadedConfig {
    pub data: Value,
    pub user_provided: Value,
    pub config_dir: PathBuf,
    pub local_overlay: LocalOverlayStatus,
}

type GetEnv<'a> = &'a dyn Fn(&str) -> Option<String>;

fn is_set_and_nonempty(getenv: GetEnv, name: &str) -> bool {
    getenv(name).map(|v| !v.is_empty()).unwrap_or(false)
}

fn config_dir_of(path: &Path) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn read_yaml_mapping(path: &Path) -> Result<Value, ConfigError> {
    if appsec_pathjail::is_network_path(&path.to_string_lossy()) {
        return Err(ConfigError::NetworkPath {
            path: path.to_path_buf(),
        });
    }
    let text = std::fs::read_to_string(path).map_err(io_err(path))?;
    parse_yaml_mapping(path, &text)
}

pub(crate) fn io_err(path: &Path) -> impl Fn(std::io::Error) -> ConfigError + '_ {
    move |e| ConfigError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    }
}

pub(crate) fn parse_yaml_mapping(path: &Path, text: &str) -> Result<Value, ConfigError> {
    let parsed = appsec_yaml::parse(text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    match parsed {
        Value::Null => Ok(Value::Object(serde_json::Map::new())),
        Value::Object(_) => Ok(parsed),
        _ => Err(ConfigError::NotAMapping {
            path: path.to_path_buf(),
        }),
    }
}

pub fn load(path: &Path, getenv: GetEnv) -> Result<LoadedConfig, ConfigError> {
    let raw = read_yaml_mapping(path)?;
    let mut merged = deep_merge(&step_defaults(), &raw);
    let mut user_provided = raw;

    let local_path = path.with_file_name("config.local.yaml");
    let skip = is_set_and_nonempty(getenv, "BC_NO_LOCAL_CONFIG");
    let local_overlay = match overlay::read_local_overlay(&local_path, skip)? {
        overlay::Overlay::Absent => LocalOverlayStatus::Absent,
        overlay::Overlay::Skipped => LocalOverlayStatus::Skipped { path: local_path },
        overlay::Overlay::Applied {
            tree,
            ownership_verified,
        } => {
            merged = deep_merge(&merged, &tree);
            user_provided = deep_merge(&user_provided, &tree);
            LocalOverlayStatus::Applied {
                path: local_path,
                overridden_leaves: banner::leaf_paths(&tree),
                ownership_verified,
            }
        }
    };

    let config_dir = config_dir_of(path);
    Ok(LoadedConfig {
        data: env::expand(&merged, "", getenv)?,
        user_provided: env::expand(&user_provided, "", getenv)?,
        config_dir,
        local_overlay,
    })
}

pub fn check_config_trust(
    config_path: &Path,
    scan_target_root: &Path,
    getenv: GetEnv,
) -> Result<(), ConfigError> {
    if appsec_pathjail::is_within(scan_target_root, config_path)
        && !is_set_and_nonempty(getenv, "BC_ALLOW_CWD_CONFIG")
    {
        return Err(ConfigError::ConfigInsideScanTarget {
            config_path: config_path.to_path_buf(),
            scan_target_root: scan_target_root.to_path_buf(),
        });
    }
    Ok(())
}

pub fn apply_step1_overlay(
    cfg: &mut Value,
    overlay_path: &Path,
    getenv: GetEnv,
) -> Result<bool, ConfigError> {
    let path_str = overlay_path.to_string_lossy();
    if appsec_pathjail::is_network_path(&path_str) {
        return Err(ConfigError::NetworkPath {
            path: overlay_path.to_path_buf(),
        });
    }
    if !overlay_path.is_file() {
        return Ok(false);
    }
    let raw = read_yaml_mapping(overlay_path)?;
    let unwrapped = match &raw {
        Value::Object(map) if map.len() == 1 && map.get("step1").is_some_and(Value::is_object) => {
            map["step1"].clone()
        }
        other => other.clone(),
    };
    let over = env::expand(&unwrapped, "step1", getenv)?;
    let base1 = cfg
        .get("step1")
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let merged1 = append_merge(&base1, &over);
    if let Value::Object(map) = cfg {
        map.insert("step1".to_string(), merged1);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn env_from(pairs: Vec<(&str, &str)>) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    fn write_overlay(dir: &Path, text: &str) -> PathBuf {
        let local = dir.join("config.local.yaml");
        std::fs::write(&local, text).unwrap();
        set_mode(&local, 0o644);
        local
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn load_merges_step_defaults_underneath_and_expands_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            "step1:\n  max_turns: 99\nsdk:\n  api_key: ${MY_KEY}\n",
        )
        .unwrap();
        let env = env_from(vec![("MY_KEY", "secret")]);
        let loaded = load(&path, &env).unwrap();
        assert_eq!(loaded.data["step1"]["max_turns"], 99);
        assert_eq!(loaded.data["step1"]["max_file_kb"], 1024);
        assert_eq!(loaded.data["sdk"]["api_key"], "secret");
        assert_eq!(loaded.local_overlay, LocalOverlayStatus::Absent);
        assert_eq!(loaded.config_dir, dir.path());
        assert_eq!(loaded.user_provided["step1"]["max_turns"], 99);
        assert_eq!(loaded.user_provided["sdk"]["api_key"], "secret");
        assert!(loaded.user_provided["step1"].get("max_file_kb").is_none());
    }

    #[test]
    fn load_empty_file_is_treated_as_empty_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "").unwrap();
        let loaded = load(&path, &no_env).unwrap();
        assert_eq!(loaded.data["step1"]["max_file_kb"], 1024);
    }

    #[test]
    fn load_rejects_non_mapping_top_level() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "- 1\n- 2\n").unwrap();
        let err = load(&path, &no_env).unwrap_err();
        assert!(matches!(err, ConfigError::NotAMapping { .. }));
    }

    #[test]
    fn load_rejects_unparseable_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "a: {unclosed\n").unwrap();
        let err = load(&path, &no_env).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn load_missing_file_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.yaml");
        let err = load(&path, &no_env).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn load_refuses_a_network_path_without_touching_the_filesystem() {
        let path = Path::new(r"\\attacker\share\config.yaml");
        let err = load(path, &no_env).unwrap_err();
        assert!(matches!(err, ConfigError::NetworkPath { .. }));
    }

    #[test]
    fn load_merges_local_overlay_on_top_after_expansion_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1:\n  max_turns: 10\n").unwrap();
        write_overlay(dir.path(), "step1:\n  max_turns: 20\n");
        let loaded = load(&path, &no_env).unwrap();
        assert_eq!(loaded.data["step1"]["max_turns"], 20);
        assert_eq!(loaded.user_provided["step1"]["max_turns"], 20);
        assert_eq!(
            loaded.local_overlay,
            LocalOverlayStatus::Applied {
                path: dir.path().join("config.local.yaml"),
                overridden_leaves: vec!["step1.max_turns".to_string()],
                ownership_verified: true,
            }
        );
    }

    #[test]
    fn load_refuses_a_group_writable_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1: {}\n").unwrap();
        let local = write_overlay(dir.path(), "step1:\n  max_turns: 20\n");
        set_mode(&local, 0o664);
        let err = load(&path, &no_env).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UntrustedOverlay { path, reason }
                if path == &local && reason.contains("writable")),
            "{err:?}"
        );
        assert!(err.to_string().contains("BC_NO_LOCAL_CONFIG"));
    }

    #[test]
    fn no_local_config_skips_an_untrusted_overlay_without_checking_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1: {}\n").unwrap();
        let local = write_overlay(dir.path(), "step1:\n  max_turns: 20\n");
        set_mode(&local, 0o666);
        let env = env_from(vec![("BC_NO_LOCAL_CONFIG", "1")]);
        let loaded = load(&path, &env).unwrap();
        assert_eq!(
            loaded.local_overlay,
            LocalOverlayStatus::Skipped { path: local }
        );
    }

    #[test]
    fn load_refuses_a_symlinked_overlay_even_to_a_trusted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1: {}\n").unwrap();
        let target = dir.path().join("elsewhere.yaml");
        std::fs::write(&target, "step1:\n  max_turns: 20\n").unwrap();
        set_mode(&target, 0o644);
        std::os::unix::fs::symlink(&target, dir.path().join("config.local.yaml")).unwrap();
        let err = load(&path, &no_env).unwrap_err();
        assert!(
            matches!(&err, ConfigError::UntrustedOverlay { reason, .. } if reason.contains("symbolic link")),
            "{err:?}"
        );
    }

    #[test]
    fn load_refuses_a_dangling_symlinked_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1: {}\n").unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("missing.yaml"),
            dir.path().join("config.local.yaml"),
        )
        .unwrap();
        let err = load(&path, &no_env).unwrap_err();
        assert!(
            matches!(err, ConfigError::UntrustedOverlay { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn load_refuses_a_secret_named_variable_in_an_ordinary_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            "step_remediate:\n  verify_command: \"make T=${GITHUB_TOKEN}\"\n",
        )
        .unwrap();
        let env = env_from(vec![("GITHUB_TOKEN", "ghp_do_not_print")]);
        let err = load(&path, &env).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("'step_remediate.verify_command'"),
            "{message}"
        );
        assert!(message.contains("'GITHUB_TOKEN'"), "{message}");
        assert!(!message.contains("ghp_do_not_print"), "{message}");
    }

    #[test]
    fn load_refuses_a_secret_named_variable_arriving_through_the_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1: {}\n").unwrap();
        write_overlay(dir.path(), "sdk:\n  api_key: ${ANTHROPIC_API_KEY}\n");
        let err = load(&path, &no_env).unwrap_err();
        assert!(
            matches!(&err, ConfigError::SecretInterpolation { key_path, .. } if key_path == "sdk.api_key"),
            "{err:?}"
        );
    }

    #[test]
    fn apply_step1_overlay_refuses_a_secret_named_variable_at_its_step1_key_path() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("step1.yaml");
        std::fs::write(&overlay, "step1:\n  exclude_dirs:\n    - ${VAULT_TOKEN}\n").unwrap();
        let mut cfg = json!({"step1": {}});
        let err = apply_step1_overlay(&mut cfg, &overlay, &no_env).unwrap_err();
        assert!(
            matches!(&err, ConfigError::SecretInterpolation { key_path, .. } if key_path == "step1.exclude_dirs"),
            "{err:?}"
        );
    }

    #[test]
    fn load_skips_local_overlay_when_no_local_config_env_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1:\n  max_turns: 10\n").unwrap();
        write_overlay(dir.path(), "step1:\n  max_turns: 20\n");
        let env = env_from(vec![("BC_NO_LOCAL_CONFIG", "1")]);
        let loaded = load(&path, &env).unwrap();
        assert_eq!(loaded.data["step1"]["max_turns"], 10);
        assert!(matches!(
            loaded.local_overlay,
            LocalOverlayStatus::Skipped { .. }
        ));
    }

    #[test]
    fn load_empty_no_local_config_env_value_does_not_count_as_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1:\n  max_turns: 10\n").unwrap();
        write_overlay(dir.path(), "step1:\n  max_turns: 20\n");
        let env = env_from(vec![("BC_NO_LOCAL_CONFIG", "")]);
        let loaded = load(&path, &env).unwrap();
        assert_eq!(loaded.data["step1"]["max_turns"], 20);
    }

    #[test]
    fn load_local_overlay_that_is_not_a_mapping_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "step1: {}\n").unwrap();
        write_overlay(dir.path(), "- not\n- a\n- mapping\n");
        let err = load(&path, &no_env).unwrap_err();
        assert!(matches!(err, ConfigError::NotAMapping { .. }));
    }

    #[test]
    fn check_config_trust_allows_a_config_outside_the_scan_target() {
        let target = tempfile::tempdir().unwrap();
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("config.yaml");
        std::fs::write(&config_path, "").unwrap();
        assert!(check_config_trust(&config_path, target.path(), &no_env).is_ok());
    }

    #[test]
    fn check_config_trust_refuses_a_config_inside_the_scan_target() {
        let target = tempfile::tempdir().unwrap();
        let config_path = target.path().join("config.yaml");
        std::fs::write(&config_path, "").unwrap();
        let err = check_config_trust(&config_path, target.path(), &no_env).unwrap_err();
        assert!(matches!(err, ConfigError::ConfigInsideScanTarget { .. }));
    }

    #[test]
    fn check_config_trust_override_env_var_allows_it_through() {
        let target = tempfile::tempdir().unwrap();
        let config_path = target.path().join("config.yaml");
        std::fs::write(&config_path, "").unwrap();
        let env = env_from(vec![("BC_ALLOW_CWD_CONFIG", "1")]);
        assert!(check_config_trust(&config_path, target.path(), &env).is_ok());
    }

    #[test]
    fn check_config_trust_empty_override_value_does_not_count() {
        let target = tempfile::tempdir().unwrap();
        let config_path = target.path().join("config.yaml");
        std::fs::write(&config_path, "").unwrap();
        let env = env_from(vec![("BC_ALLOW_CWD_CONFIG", "")]);
        assert!(check_config_trust(&config_path, target.path(), &env).is_err());
    }

    #[test]
    fn apply_step1_overlay_refuses_network_path() {
        let mut cfg = json!({"step1": {}});
        let err = apply_step1_overlay(&mut cfg, Path::new(r"\\attacker\share\x.yaml"), &no_env)
            .unwrap_err();
        assert!(matches!(err, ConfigError::NetworkPath { .. }));
    }

    #[test]
    fn apply_step1_overlay_missing_file_is_a_no_op() {
        let mut cfg = json!({"step1": {"exclude_dirs": ["a"]}});
        let applied =
            apply_step1_overlay(&mut cfg, Path::new("/does/not/exist.yaml"), &no_env).unwrap();
        assert!(!applied);
        assert_eq!(cfg["step1"]["exclude_dirs"], json!(["a"]));
    }

    #[test]
    fn apply_step1_overlay_bare_key_file_appends_lists() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("step1.yaml");
        std::fs::write(&overlay, "exclude_dirs:\n  - custom_dir\n").unwrap();
        let mut cfg = json!({"step1": {"exclude_dirs": ["a"]}});
        let applied = apply_step1_overlay(&mut cfg, &overlay, &no_env).unwrap();
        assert!(applied);
        assert_eq!(cfg["step1"]["exclude_dirs"], json!(["a", "custom_dir"]));
    }

    #[test]
    fn apply_step1_overlay_wrapped_in_step1_key_is_unwrapped() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("step1.yaml");
        std::fs::write(&overlay, "step1:\n  exclude_dirs:\n    - wrapped_dir\n").unwrap();
        let mut cfg = json!({"step1": {"exclude_dirs": ["a"]}});
        apply_step1_overlay(&mut cfg, &overlay, &no_env).unwrap();
        assert_eq!(cfg["step1"]["exclude_dirs"], json!(["a", "wrapped_dir"]));
    }

    #[test]
    fn apply_step1_overlay_expands_env_placeholders() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("step1.yaml");
        std::fs::write(&overlay, "max_file_kb: ${MAX_KB}\n").unwrap();
        let mut cfg = json!({"step1": {}});
        let env = env_from(vec![("MAX_KB", "2048")]);
        apply_step1_overlay(&mut cfg, &overlay, &env).unwrap();
        assert_eq!(cfg["step1"]["max_file_kb"], "2048");
    }

    #[test]
    fn apply_step1_overlay_creates_step1_key_when_absent_from_cfg() {
        let dir = tempfile::tempdir().unwrap();
        let overlay = dir.path().join("step1.yaml");
        std::fs::write(&overlay, "exclude_dirs:\n  - a\n").unwrap();
        let mut cfg = json!({});
        apply_step1_overlay(&mut cfg, &overlay, &no_env).unwrap();
        assert_eq!(cfg["step1"]["exclude_dirs"], json!(["a"]));
    }

    #[test]
    fn config_error_display_messages() {
        let io = ConfigError::Io {
            path: PathBuf::from("/a"),
            message: "boom".to_string(),
        };
        assert_eq!(io.to_string(), "/a: boom");
        let not_map = ConfigError::NotAMapping {
            path: PathBuf::from("/a"),
        };
        assert!(not_map.to_string().contains("must be a YAML mapping"));
        let net = ConfigError::NetworkPath {
            path: PathBuf::from(r"\\h\s"),
        };
        assert!(net.to_string().contains("network/UNC"));
        let inside = ConfigError::ConfigInsideScanTarget {
            config_path: PathBuf::from("/r/config.yaml"),
            scan_target_root: PathBuf::from("/r"),
        };
        assert!(inside.to_string().contains("BC_ALLOW_CWD_CONFIG"));
        let parse = ConfigError::Parse {
            path: PathBuf::from("/a"),
            message: "bad yaml".to_string(),
        };
        assert_eq!(parse.to_string(), "/a: bad yaml");
        let secret = ConfigError::SecretInterpolation {
            key_path: String::new(),
            var: "API_TOKEN".to_string(),
        };
        assert!(secret.to_string().contains("config key '(root)'"));
        assert!(secret.to_string().contains("no config key"));
        let untrusted = ConfigError::UntrustedOverlay {
            path: PathBuf::from("/c/config.local.yaml"),
            reason: "it is a symbolic link".to_string(),
        };
        assert!(untrusted.to_string().starts_with(
            "config overlay /c/config.local.yaml is not trusted: it is a symbolic link."
        ));
    }

    #[test]
    fn config_error_implements_std_error() {
        let e = ConfigError::NotAMapping {
            path: PathBuf::from("/a"),
        };
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn local_overlay_status_path_names_the_overlay_when_there_is_one() {
        let p = PathBuf::from("/c/config.local.yaml");
        assert_eq!(LocalOverlayStatus::Absent.path(), None);
        assert_eq!(
            LocalOverlayStatus::Skipped { path: p.clone() }.path(),
            Some(p.as_path())
        );
        let applied = LocalOverlayStatus::Applied {
            path: p.clone(),
            overridden_leaves: Vec::new(),
            ownership_verified: true,
        };
        assert_eq!(applied.path(), Some(p.as_path()));
    }

    #[test]
    fn config_dir_of_falls_back_to_dot_when_path_has_no_parent() {
        assert_eq!(config_dir_of(Path::new("/")), PathBuf::from("."));
    }
}
