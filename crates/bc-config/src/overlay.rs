//! The `config.local.yaml` trust gate, ported from
//! `vvaharness/config/__init__.py`'s `_local_overlay_trusted`,
//! `_require_overlay_trust` and `_local_overlay` (v1.3.0).
//!
//! The overlay can override security-relevant keys (model routing, tool
//! permissions, `step_remediate.verify_command`), and it is picked up
//! implicitly, with no flag naming it. So it is honored only when it
//! could not have been planted by somebody else: owned by the invoking
//! user (or root) and not group- or world-writable.
//!
//! Two deliberate hardenings over Python, which `stat()`s through a
//! symlink and then re-opens the path to read it:
//! - a symlinked overlay is refused outright, since the link could point
//!   at a file some other user controls, and
//! - the file is opened once, the trust facts are read from that open
//!   handle, and the same handle is read, with a check that the handle and
//!   the directory entry name the same file. Nothing can be swapped in
//!   between the check and the read.

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::Path;

use serde_json::Value;

use crate::{io_err, parse_yaml_mapping, ConfigError};

/// The reason reported for a symlinked overlay.
const SYMLINK_REASON: &str =
    "it is a symbolic link (a link could point at a file another user controls); \
     replace it with a regular file";

/// Everything the trust decision reads, gathered by the I/O layer so the
/// decision itself is a pure function testable without root, `chown` or
/// a second user account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayFacts {
    pub is_symlink: bool,
    /// The opened handle and the directory entry name different files: the
    /// entry changed between the two looks.
    pub swapped: bool,
    pub owner_uid: u32,
    /// `st_mode`, of which only the group/other write bits are read.
    pub mode: u32,
    /// The effective uid of this process.
    pub euid: u32,
}

/// `Ok` when an overlay with these facts may be merged, else the reason
/// it may not (which never contains file content).
pub fn overlay_trust_verdict(facts: &OverlayFacts) -> Result<(), String> {
    if facts.is_symlink {
        return Err(SYMLINK_REASON.to_string());
    }
    if facts.swapped {
        return Err("it was replaced while being checked".to_string());
    }
    if facts.owner_uid != facts.euid && facts.owner_uid != 0 {
        return Err(format!(
            "it is owned by uid {}, not the invoking user (uid {}) or root",
            facts.owner_uid, facts.euid
        ));
    }
    if facts.mode & 0o022 != 0 {
        return Err(format!(
            "it is group- or world-writable (mode {:o})",
            facts.mode & 0o7777
        ));
    }
    Ok(())
}

/// What [`read_local_overlay`] found.
#[derive(Debug, PartialEq)]
pub(crate) enum Overlay {
    Absent,
    Skipped,
    Applied {
        tree: Value,
        /// `false` only on a platform without POSIX ownership (Windows),
        /// where the overlay is honored unchecked, as in Python.
        ownership_verified: bool,
    },
}

/// Trust-check and read the overlay at `local`. `skip` is the
/// `BC_NO_LOCAL_CONFIG` escape hatch, consulted before the trust check (as
/// in Python) so an operator can always get past an untrusted overlay
/// without deleting it.
pub(crate) fn read_local_overlay(local: &Path, skip: bool) -> Result<Overlay, ConfigError> {
    // Any error (almost always NotFound) is "absent", as Python's
    // `Path.exists()` and this crate's earlier `is_file()` both treat it.
    let Ok(entry) = std::fs::symlink_metadata(local) else {
        return Ok(Overlay::Absent);
    };
    let is_symlink = entry.file_type().is_symlink();
    if !is_symlink && !entry.is_file() {
        return Ok(Overlay::Absent);
    }
    if skip {
        return Ok(Overlay::Skipped);
    }
    // Refused before opening: opening would follow the link.
    if is_symlink {
        return Err(untrusted(local, SYMLINK_REASON.to_string()));
    }
    let mut file = File::open(local).map_err(io_err(local))?;
    let opened = file.metadata().map_err(io_err(local))?;
    let ownership_verified = check_trust(local, &entry, &opened)?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(io_err(local))?;
    Ok(Overlay::Applied {
        tree: parse_yaml_mapping(local, &text)?,
        ownership_verified,
    })
}

fn untrusted(path: &Path, reason: String) -> ConfigError {
    ConfigError::UntrustedOverlay {
        path: path.to_path_buf(),
        reason,
    }
}

/// Applies [`overlay_trust_verdict`]; returns whether ownership was
/// actually verified.
#[cfg(unix)]
fn check_trust(local: &Path, entry: &Metadata, opened: &Metadata) -> Result<bool, ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let facts = OverlayFacts {
        is_symlink: false,
        swapped: (entry.dev(), entry.ino()) != (opened.dev(), opened.ino()),
        owner_uid: opened.uid(),
        mode: opened.mode(),
        euid: rustix::process::geteuid().as_raw(),
    };
    overlay_trust_verdict(&facts).map_err(|reason| untrusted(local, reason))?;
    Ok(true)
}

/// No POSIX owner or mode bits to check. Python logs "ownership
/// unverified" and proceeds; so does this port, through
/// `LocalOverlayStatus::Applied::ownership_verified`.
#[cfg(not(unix))]
fn check_trust(_local: &Path, _entry: &Metadata, _opened: &Metadata) -> Result<bool, ConfigError> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EUID: u32 = 1000;

    fn trusted() -> OverlayFacts {
        OverlayFacts {
            is_symlink: false,
            swapped: false,
            owner_uid: EUID,
            mode: 0o100644,
            euid: EUID,
        }
    }

    #[test]
    fn an_own_non_writable_regular_file_is_trusted() {
        assert_eq!(overlay_trust_verdict(&trusted()), Ok(()));
    }

    #[test]
    fn a_root_owned_file_is_trusted() {
        let facts = OverlayFacts {
            owner_uid: 0,
            ..trusted()
        };
        assert_eq!(overlay_trust_verdict(&facts), Ok(()));
    }

    #[test]
    fn a_file_owned_by_another_user_is_refused() {
        let facts = OverlayFacts {
            owner_uid: 4242,
            ..trusted()
        };
        let reason = overlay_trust_verdict(&facts).unwrap_err();
        assert!(reason.contains("uid 4242"), "{reason}");
        assert!(reason.contains("uid 1000"), "{reason}");
    }

    #[test]
    fn group_or_world_write_is_refused() {
        for mode in [0o100664, 0o100646, 0o100666] {
            let facts = OverlayFacts { mode, ..trusted() };
            let reason = overlay_trust_verdict(&facts).unwrap_err();
            assert!(reason.contains("writable"), "{reason}");
        }
    }

    #[test]
    fn a_symlink_is_refused_even_when_everything_else_is_fine() {
        let facts = OverlayFacts {
            is_symlink: true,
            ..trusted()
        };
        assert!(overlay_trust_verdict(&facts)
            .unwrap_err()
            .contains("symbolic link"));
    }

    #[test]
    fn a_file_swapped_between_the_check_and_the_open_is_refused() {
        let facts = OverlayFacts {
            swapped: true,
            ..trusted()
        };
        assert!(overlay_trust_verdict(&facts)
            .unwrap_err()
            .contains("replaced"));
    }

    #[test]
    fn a_missing_overlay_or_a_directory_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("config.local.yaml");
        assert_eq!(read_local_overlay(&local, false).unwrap(), Overlay::Absent);
        std::fs::create_dir(&local).unwrap();
        assert_eq!(read_local_overlay(&local, false).unwrap(), Overlay::Absent);
    }

    #[test]
    fn an_overlay_that_is_not_utf8_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("config.local.yaml");
        std::fs::write(&local, [0xff, 0xfe, 0x00]).unwrap();
        let err = read_local_overlay(&local, false).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }), "{err:?}");
    }

    #[test]
    fn an_own_overlay_is_applied_and_reports_verified_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("config.local.yaml");
        std::fs::write(&local, "a: 1\n").unwrap();
        // Pinned so the test does not depend on the runner's umask.
        std::fs::set_permissions(&local, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        assert_eq!(
            read_local_overlay(&local, false).unwrap(),
            Overlay::Applied {
                tree: serde_json::json!({"a": 1}),
                ownership_verified: true,
            }
        );
    }
}
