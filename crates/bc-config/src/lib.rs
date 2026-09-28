//! Config loading, ported from `vvaharness/config/__init__.py`: YAML
//! load, built-in step-defaults merge, `config.local.yaml` overlay, and
//! `${VAR}` env expansion — plus the `is_network_path`/in-target-config
//! trust-gate checks and the `--step1-config` overlay merge.
//!
//! Environment lookups are threaded through as a `&dyn Fn(&str) ->
//! Option<String>` parameter rather than calling `std::env::var`
//! directly, so the merge/expansion logic stays pure and testable; only
//! [`load`] and [`apply_step1_overlay`] touch the filesystem, and they do
//! so through ordinary `std::fs` calls with no hidden global state.
//!
//! Deliberately does **not** log anything itself (the Python original
//! prints config-overlay provenance to stderr as a side effect of
//! `load()`) — [`LoadedConfig`] reports what happened
//! (`local_overlay`, which [`render_overlay_banner`] turns into the
//! provenance line) so a higher-tier CLI layer decides how and how often
//! to surface it, keeping this crate's core logic free of I/O side effects
//! beyond the file reads it must do.
//!
//! Two security policies from upstream v1.3.0 live here: secret-named
//! variables may not be interpolated into ordinary keys ([`policy`]), and
//! `config.local.yaml` is merged only when its ownership and mode show it
//! could not have been planted by another user ([`overlay_trust_verdict`]).

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
    /// A secret-named environment variable interpolated into a key that
    /// may not carry a credential (see [`policy`]). Names the key and the
    /// variable, never the value.
    SecretInterpolation {
        key_path: String,
        var: String,
    },
    /// `config.local.yaml` failed the ownership/mode/symlink trust gate.
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

/// Whether a sibling `config.local.yaml` was found next to the loaded
/// config, and if so, whether it was actually merged in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalOverlayStatus {
    Absent,
    Applied {
        path: PathBuf,
        /// Dotted key path of every leaf the overlay sets, in document
        /// order (lists and empty maps count as leaves). Feeds
        /// [`render_overlay_banner`].
        overridden_leaves: Vec<String>,
        /// `false` only where POSIX ownership cannot be checked
        /// (non-Unix), in which case the overlay is merged unchecked, as in
        /// Python, and the banner says so.
        ownership_verified: bool,
    },
    Skipped {
        path: PathBuf,
    },
}

impl LocalOverlayStatus {
    /// The overlay file this status is about, if one was found. Lets a
    /// caller key "already announced" bookkeeping on it.
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
    /// `data` without [`step_defaults`] merged underneath — just the
    /// requested file plus `config.local.yaml` if present, env-expanded.
    /// Lets a caller distinguish "the user's own config never mentioned
    /// this key" from "the key is present only because a built-in default
    /// filled it in" for an optional override whose *baked-in* default
    /// differs between this crate's `step_defaults()` and a caller's own
    /// intended default — reading `data` alone for that case would treat
    /// "not mentioned" and "explicitly set back to the built-in value" as
    /// indistinguishable, silently discarding the caller's own default the
    /// moment any config file is loaded at all.
    pub user_provided: Value,
    pub config_dir: PathBuf,
    pub local_overlay: LocalOverlayStatus,
}

type GetEnv<'a> = &'a dyn Fn(&str) -> Option<String>;

fn is_set_and_nonempty(getenv: GetEnv, name: &str) -> bool {
    getenv(name).map(|v| !v.is_empty()).unwrap_or(false)
}

/// `path.parent()` returns `None` only for `"/"`, `""`, or `"//"` — none of
/// which `fs::read_to_string` can ever successfully read as a regular file,
/// so this fallback is unreachable through [`load`]'s real call path. Kept
/// as an explicit, directly-tested helper rather than an
/// `unreachable!()`/`.expect()` in [`load`] itself, since a caller-supplied
/// `path` is not a value this crate controls.
fn config_dir_of(path: &Path) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

/// Shared load choke point for `--config` and `--step1-config`: checks
/// for a network (UNC/`\\host\share`) path before any filesystem touch
/// (even a failed read would trigger Windows' SMB handshake and leak the
/// caller's NTLMv2 hash to a malicious host), then reads and parses `path`
/// as a YAML mapping. (`config.local.yaml` sits next to an already-checked
/// `--config` path and goes through [`overlay`]'s trust gate instead.)
fn read_yaml_mapping(path: &Path) -> Result<Value, ConfigError> {
    if bc_pathjail::is_network_path(&path.to_string_lossy()) {
        return Err(ConfigError::NetworkPath {
            path: path.to_path_buf(),
        });
    }
    let text = std::fs::read_to_string(path).map_err(io_err(path))?;
    parse_yaml_mapping(path, &text)
}

/// Maps an I/O error on `path` to [`ConfigError::Io`]. One shared closure
/// for every read in this crate.
pub(crate) fn io_err(path: &Path) -> impl Fn(std::io::Error) -> ConfigError + '_ {
    move |e| ConfigError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    }
}

/// Parses already-read `text` from `path` as a YAML mapping (an empty
/// document is an empty mapping).
pub(crate) fn parse_yaml_mapping(path: &Path, text: &str) -> Result<Value, ConfigError> {
    let parsed = bc_yaml::parse(text).map_err(|e| ConfigError::Parse {
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

/// Load `path`, deep-merge the built-in [`step_defaults`] underneath it,
/// merge a sibling `config.local.yaml` on top if present and trusted
/// (unless `BC_NO_LOCAL_CONFIG` is set to a non-empty value), then expand
/// `${VAR}` placeholders across the fully-merged tree under the
/// secret-name policy.
///
/// Fails with [`ConfigError::UntrustedOverlay`] for an overlay that is a
/// symlink, owned by another user, or group/world-writable, and with
/// [`ConfigError::SecretInterpolation`] for a secret-named `${VAR}` in any
/// key (see [`policy`]).
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

/// Refuse a config path that resolves *inside* the scan target itself —
/// defeats the "attacker checks in a malicious config.yaml, CI cd's into
/// the repo and scans" attack — unless explicitly overridden via
/// `BC_ALLOW_CWD_CONFIG`.
pub fn check_config_trust(
    config_path: &Path,
    scan_target_root: &Path,
    getenv: GetEnv,
) -> Result<(), ConfigError> {
    if bc_pathjail::is_within(scan_target_root, config_path)
        && !is_set_and_nonempty(getenv, "BC_ALLOW_CWD_CONFIG")
    {
        return Err(ConfigError::ConfigInsideScanTarget {
            config_path: config_path.to_path_buf(),
            scan_target_root: scan_target_root.to_path_buf(),
        });
    }
    Ok(())
}

/// Layer a per-scan `--step1-config` overlay onto `cfg.step1`. Accepts
/// either a bare-key file (`exclude_dirs: [...]`) or one wrapped in a
/// top-level `step1:` block. Lists append; nested dicts replace; scalars
/// replace. Returns whether the overlay file existed and was applied.
pub fn apply_step1_overlay(
    cfg: &mut Value,
    overlay_path: &Path,
    getenv: GetEnv,
) -> Result<bool, ConfigError> {
    let path_str = overlay_path.to_string_lossy();
    if bc_pathjail::is_network_path(&path_str) {
        return Err(ConfigError::NetworkPath {
            path: overlay_path.to_path_buf(),
        });
    }
    if !overlay_path.is_file() {
        return Ok(false);
    }
    let raw = read_yaml_mapping(overlay_path)?;
    // Unwrapped before expansion (as in Python) so the policy sees the key
    // path each value will actually land at: `step1.<key>`.
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

    /// Writes `config.local.yaml` in `dir` with mode 0644, so a test does
    /// not depend on the runner's umask (under a 002 umask the file would
    /// be group-writable and, correctly, refused).
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
        assert_eq!(loaded.data["step1"]["max_turns"], 99); // user override wins
        assert_eq!(loaded.data["step1"]["max_file_kb"], 1024); // default fills the gap
        assert_eq!(loaded.data["sdk"]["api_key"], "secret");
        assert_eq!(loaded.local_overlay, LocalOverlayStatus::Absent);
        assert_eq!(loaded.config_dir, dir.path());
        // user_provided excludes step_defaults entirely: the user's own
        // key is present (env-expanded), but a step_defaults-only field
        // like max_file_kb never appears at all.
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
        assert_eq!(loaded.data["step1"]["max_turns"], 20); // local wins
        assert_eq!(loaded.user_provided["step1"]["max_turns"], 20); // local wins here too
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
        // chmod works as root too, and the refusal is about the file's
        // own mode bits, so this holds whoever runs the test.
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
        assert_eq!(loaded.data["step1"]["max_turns"], 10); // local overlay skipped
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
        assert_eq!(loaded.data["step1"]["max_turns"], 20); // overlay still applied
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
        // "/" (and "" / "//") are the only inputs where `Path::parent()`
        // returns `None` -- unreachable through `load()` itself since none
        // of them can be a readable regular file, so exercised directly.
        assert_eq!(config_dir_of(Path::new("/")), PathBuf::from("."));
    }
}
