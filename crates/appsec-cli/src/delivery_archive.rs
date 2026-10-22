//! Isolated source delivery without Git or external archive executables.
//!
//! ZIP uses the deliberately small STORE subset (UTF-8 names, CRC32, Unix
//! executable bits, no ZIP64). The copy budget is below all ZIP32 limits.
//! Named sensitive files are omitted, not a claim that arbitrary source is
//! secret-free. Callers must report `excluded_paths` and retain normal review.
use std::fs::{self, File};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 30_000;
const MAX_DEPTH: usize = 32;

#[derive(Debug)]
pub struct Snapshot {
    directory: tempfile::TempDir,
    pub excluded_paths: Vec<String>,
}

impl Snapshot {
    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Preserve reviewable work when delivery fails or retention was requested.
    pub fn keep(self) -> PathBuf {
        self.directory.keep()
    }
}

#[derive(Default)]
struct Inventory {
    files: Vec<(String, PathBuf, u32)>,
    directories: Vec<String>,
    excluded: Vec<String>,
    entries: usize,
    bytes: u64,
}

fn excluded(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with(".env")
        || matches!(
            name.as_str(),
            ".git"
                | "security-scan"
                | "credentials"
                | "credentials.json"
                | "secrets.json"
                | "secrets.yaml"
                | "secrets.yml"
                | "id_rsa"
                | "id_ed25519"
                | ".aws"
                | ".ssh"
                | ".azure"
                | ".kube"
                | ".npmrc"
                | ".pypirc"
                | "node_modules"
                | "target"
                | "vendor"
                | ".venv"
                | "venv"
                | ".tox"
                | "dist"
                | "build"
                | ".next"
                | "coverage"
                | "__pycache__"
        )
        || [".pem", ".key", ".p12", ".pfx", ".kdbx"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn safe_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && !name
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
        && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn inventory(root: &Path) -> Result<Inventory, String> {
    let root = root
        .canonicalize()
        .map_err(crate::context("cannot resolve source"))?;
    if !root.is_dir() {
        return Err("source must be a directory".into());
    }
    let mut found = Inventory::default();
    walk(&root, "", 0, &mut found)?;
    Ok(found)
}

fn walk(root: &Path, relative: &str, depth: usize, found: &mut Inventory) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("source exceeds archive depth limit (32)".into());
    }
    let entries = fs::read_dir(root).map_err(crate::context("cannot enumerate source"))?;
    let mut entries = entries
        .take(MAX_ENTRIES + 1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(crate::context("cannot enumerate source"))?;
    entries.sort_by_key(|e| e.file_name());
    let mut names = std::collections::HashSet::new();
    for entry in entries {
        found.entries += 1;
        if found.entries > MAX_ENTRIES {
            return Err("source exceeds archive entry limit (30000)".into());
        }
        let raw = entry.file_name();
        let name = raw.to_str().ok_or("source contains a non-UTF-8 filename")?;
        let relative = if relative.is_empty() {
            name.to_owned()
        } else {
            format!("{relative}/{name}")
        };
        if excluded(name) {
            found.excluded.push(relative);
            continue;
        }
        if !safe_name(name) || relative.len() >= u16::MAX as usize {
            return Err(format!(
                "source filename is not portable or safe for ZIP: {relative:?}"
            ));
        }
        if !names.insert(name.to_lowercase()) {
            return Err(format!(
                "source has a case-insensitive filename collision: {relative}"
            ));
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(crate::context("cannot inspect source"))?;
        if meta.file_type().is_symlink() {
            found.excluded.push(relative);
        } else if meta.is_dir() {
            found.directories.push(relative.clone());
            walk(&path, &relative, depth + 1, found)?;
        } else if meta.is_file() {
            found.bytes = found
                .bytes
                .checked_add(meta.len())
                .ok_or("source byte count overflow")?;
            if found.bytes > MAX_BYTES {
                return Err("source exceeds archive byte limit (256 MiB)".into());
            }
            found.files.push((relative, path, file_mode(&meta)));
        } else {
            return Err(format!(
                "source contains an unsupported special file: {relative}"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    }
}
#[cfg(not(unix))]
fn file_mode(_: &fs::Metadata) -> u32 {
    0o100644
}

fn open_regular(path: &Path) -> Result<File, String> {
    // Recheck immediately before opening. Source trees must remain quiescent;
    // portable std does not provide atomic no-follow directory traversal.
    let meta = fs::symlink_metadata(path).map_err(crate::context("cannot inspect source file"))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err("source changed to a non-regular file".into());
    }
    File::open(path).map_err(crate::context("cannot open source file"))
}

pub fn create_snapshot(root: &Path) -> Result<Snapshot, String> {
    let found = inventory(root)?;
    let directory = tempfile::Builder::new()
        .prefix("bc-sast-delivery-")
        .tempdir()
        .map_err(crate::context("cannot create isolated source snapshot"))?;
    for name in &found.directories {
        fs::create_dir(directory.path().join(name))
            .map_err(crate::context("cannot create snapshot directory"))?;
    }
    let mut remaining = MAX_BYTES;
    for (name, source, mode) in &found.files {
        let mut input = open_regular(source)?.take(remaining + 1);
        let destination = directory.path().join(name);
        let mut output =
            File::create(&destination).map_err(crate::context("cannot create snapshot file"))?;
        let bytes = std::io::copy(&mut input, &mut output)
            .map_err(crate::context("cannot copy snapshot file"))?;
        remaining = remaining
            .checked_sub(bytes)
            .ok_or("source grew beyond snapshot byte limit")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&destination, fs::Permissions::from_mode(mode & 0o777))
                .map_err(crate::context("cannot preserve executable permission"))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
    }
    Ok(Snapshot {
        directory,
        excluded_paths: found.excluded,
    })
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn u16le(output: &mut impl Write, value: u16) -> std::io::Result<()> {
    output.write_all(&value.to_le_bytes())
}
fn u32le(output: &mut impl Write, value: u32) -> std::io::Result<()> {
    output.write_all(&value.to_le_bytes())
}

/// Publish a complete filtered source archive, atomically, without overwriting
/// an existing artifact. The caller selects and jails the output path.
pub fn export_zip(root: &Path, output: &Path) -> Result<(), String> {
    let found = inventory(root)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut archive = tempfile::NamedTempFile::new_in(parent)
        .map_err(crate::context("cannot stage ZIP artifact"))?;
    write_zip(&mut archive, found).map_err(crate::context("cannot write ZIP artifact"))?;
    archive
        .as_file()
        .sync_all()
        .map_err(crate::context("cannot sync ZIP artifact"))?;
    // Like the scanner's other exported reports, the artifact must be
    // readable by the CI uploader when a container uses a different UID.
    // Private staging directories remain private; only the final export is shared.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        archive
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(crate::context("cannot set CI artifact permissions"))?;
    }
    archive.persist_noclobber(output).map_err(|e| {
        format!(
            "cannot publish ZIP artifact (existing artifacts are not overwritten): {}",
            e.error
        )
    })?;
    Ok(())
}

fn write_zip(output: &mut (impl Write + Seek), found: Inventory) -> std::io::Result<()> {
    struct Central {
        name: String,
        crc: u32,
        size: u32,
        offset: u32,
        mode: u32,
    }
    let mut central = Vec::new();
    let mut entries = found.files;
    entries.extend(
        found
            .directories
            .into_iter()
            .map(|name| (format!("{name}/"), PathBuf::new(), 0o40755)),
    );
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut remaining = MAX_BYTES;
    for (name, path, mode) in entries {
        let mut bytes = Vec::new();
        if !name.ends_with('/') {
            open_regular(&path)
                .map_err(std::io::Error::other)?
                .take(remaining + 1)
                .read_to_end(&mut bytes)?;
            remaining = remaining
                .checked_sub(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("source grew beyond archive limit"))?;
        }
        let crc = crc32(&bytes);
        let size = bytes.len() as u32;
        let offset = u32::try_from(output.stream_position()?).map_err(std::io::Error::other)?;
        u32le(output, 0x04034b50)?;
        for value in [20, 0x0800, 0, 0, 33] {
            u16le(output, value)?;
        }
        for value in [crc, size, size] {
            u32le(output, value)?;
        }
        u16le(output, name.len() as u16)?;
        u16le(output, 0)?;
        output.write_all(name.as_bytes())?;
        output.write_all(&bytes)?;
        central.push(Central {
            name,
            crc,
            size,
            offset,
            mode,
        });
    }
    let start = u32::try_from(output.stream_position()?).map_err(std::io::Error::other)?;
    for entry in &central {
        u32le(output, 0x02014b50)?;
        for value in [0x0314, 20, 0x0800, 0, 0, 33] {
            u16le(output, value)?;
        }
        for value in [entry.crc, entry.size, entry.size] {
            u32le(output, value)?;
        }
        for value in [entry.name.len() as u16, 0, 0, 0, 0] {
            u16le(output, value)?;
        }
        u32le(
            output,
            (entry.mode << 16) | if entry.name.ends_with('/') { 0x10 } else { 0 },
        )?;
        u32le(output, entry.offset)?;
        output.write_all(entry.name.as_bytes())?;
    }
    let length = u32::try_from(output.stream_position()?).map_err(std::io::Error::other)? - start;
    u32le(output, 0x06054b50)?;
    for value in [0, 0, central.len() as u16, central.len() as u16] {
        u16le(output, value)?;
    }
    u32le(output, length)?;
    u32le(output, start)?;
    u16le(output, 0)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_preserves_source_tests_and_records_exclusions() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("tests")).unwrap();
        fs::write(root.path().join("tests/test_app.py"), "assert True").unwrap();
        fs::write(root.path().join(".env"), "TOKEN=secret").unwrap();
        fs::create_dir(root.path().join("security-scan")).unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        assert_eq!(
            fs::read(snapshot.path().join("tests/test_app.py")).unwrap(),
            b"assert True"
        );
        assert_eq!(snapshot.excluded_paths, [".env", "security-scan"]);
        fs::write(snapshot.path().join("tests/test_app.py"), "changed").unwrap();
        assert_eq!(
            fs::read(root.path().join("tests/test_app.py")).unwrap(),
            b"assert True"
        );
    }
    #[test]
    fn zip_contains_source_and_tests_with_valid_headers_crc_and_directory() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.txt"), b"123456789").unwrap();
        fs::create_dir(root.path().join("tests")).unwrap();
        fs::write(root.path().join("tests/unit.txt"), b"pass").unwrap();
        let out = tempfile::tempdir().unwrap();
        let artifact = out.path().join("source.zip");
        export_zip(root.path(), &artifact).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
        let data = fs::read(&artifact).unwrap();
        assert_eq!(&data[..4], b"PK\x03\x04");
        assert_eq!(
            u32::from_le_bytes(data[14..18].try_into().unwrap()),
            0xcbf43926
        );
        assert_eq!(&data[30..37], b"app.txt");
        let end = data.len() - 22;
        assert_eq!(&data[end..end + 4], b"PK\x05\x06");
        assert_eq!(
            u16::from_le_bytes(data[end + 10..end + 12].try_into().unwrap()),
            3
        );
        let central = u32::from_le_bytes(data[end + 16..end + 20].try_into().unwrap()) as usize;
        assert_eq!(&data[central..central + 4], b"PK\x01\x02");
        assert!(export_zip(root.path(), &artifact).is_err());
        assert_eq!(fs::read(artifact).unwrap(), data);
    }
    #[test]
    fn portable_names_and_crc_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        for name in ["..", "a\\b", "a:b", "CON.txt", "lpt1", "trailing.", "a\n"] {
            assert!(!safe_name(name));
        }
        assert!(safe_name("tést.rs"));
    }
    #[cfg(unix)]
    #[test]
    fn snapshot_omits_symlinks_and_preserves_executables() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("run.sh"), "true").unwrap();
        fs::set_permissions(
            root.path().join("run.sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink("/etc/passwd", root.path().join("alias")).unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        assert_eq!(snapshot.excluded_paths, ["alias"]);
        assert!(!snapshot.path().join("alias").exists());
        assert_ne!(
            fs::metadata(snapshot.path().join("run.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
    #[test]
    fn rejects_case_collisions_when_filesystem_supports_them() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("test.rs"), "a").unwrap();
        fs::write(root.path().join("TEST.rs"), "b").unwrap();
        if fs::read_dir(root.path()).unwrap().count() == 2 {
            assert!(create_snapshot(root.path()).is_err());
        }
    }

    fn inventory_error(root: &Path) -> String {
        inventory(root).err().expect("inventory must fail")
    }

    #[test]
    fn a_retained_snapshot_outlives_its_temporary_directory() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.txt"), b"fixed").unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        let temporary = snapshot.path().to_path_buf();
        let kept = snapshot.keep();
        assert_eq!(kept, temporary);
        assert_eq!(fs::read(kept.join("app.txt")).unwrap(), b"fixed");
        fs::remove_dir_all(&kept).unwrap();
    }

    #[test]
    fn a_source_that_is_not_a_readable_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("app.txt");
        fs::write(&file, b"fixed").unwrap();
        assert_eq!(inventory_error(&file), "source must be a directory");
        assert!(inventory_error(&root.path().join("missing")).contains("cannot resolve source"));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_source_directory_fails_the_archive_instead_of_omitting_it() {
        use std::os::unix::fs::PermissionsExt;
        // Only a permission bit can make a directory that `lstat` accepts
        // unlistable, and root ignores it, so this runs only where
        // permissions are enforced. The listing failure itself is covered
        // for root too, by `a_source_directory_that_cannot_be_listed_fails_the_walk`.
        if crate::test_support::permissions_enforced(
            "an_unreadable_source_directory_fails_the_archive_instead_of_omitting_it",
        ) {
            let root = tempfile::tempdir().unwrap();
            let locked = root.path().join("locked");
            fs::create_dir(&locked).unwrap();
            fs::write(locked.join("app.txt"), b"fixed").unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            let outcome = inventory(root.path()).err();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(outcome.unwrap().contains("cannot enumerate source"));
        }
    }

    #[test]
    fn a_source_directory_that_cannot_be_listed_fails_the_walk() {
        // A path under a regular file cannot be listed (ENOTDIR) by any
        // user, root included, and the walk reports it rather than
        // treating the directory as empty.
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.txt"), b"fixed").unwrap();
        let mut found = Inventory::default();
        let outcome = walk(&root.path().join("app.txt/src"), "src", 1, &mut found);
        assert!(outcome.unwrap_err().contains("cannot enumerate source"));
        assert!(found.files.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_source_entry_that_cannot_be_inspected_fails_the_archive() {
        // The directory is named by its parent's listing but cannot be
        // inspected, so the archive would silently omit it. In the field
        // that is a parent with read but not search permission, which
        // root ignores; here the entry's full path exceeds `PATH_MAX`,
        // which fails for every user.
        let base = tempfile::tempdir().unwrap();
        let staged = base.path().join("staged");
        let listed = staged.join("l".repeat(200));
        fs::create_dir_all(&listed).unwrap();
        fs::write(listed.join("app.txt"), b"fixed").unwrap();
        let root = crate::test_support::bury_near_path_max(&staged);
        let outcome = inventory(&root).err();
        assert!(outcome.unwrap().contains("cannot inspect source"));
    }

    #[cfg(unix)]
    #[test]
    fn a_source_file_the_scanner_cannot_read_fails_both_the_snapshot_and_the_zip() {
        // The inventory only stats; the copy and the archive both have to
        // open the file, and neither may quietly ship a truncated tree.
        use std::os::unix::fs::PermissionsExt;
        // Only a permission bit can make a file inside the source tree
        // unopenable, and root ignores it, so this runs only where
        // permissions are enforced. The open failure is covered for root
        // too, by `only_a_regular_readable_file_is_opened_for_the_archive`
        // and `a_source_file_that_cannot_be_opened_fails_the_zip_writer`.
        if crate::test_support::permissions_enforced(
            "a_source_file_the_scanner_cannot_read_fails_both_the_snapshot_and_the_zip",
        ) {
            let root = tempfile::tempdir().unwrap();
            let locked = root.path().join("app.txt");
            fs::write(&locked, b"fixed").unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            let out = tempfile::tempdir().unwrap();
            let artifact = out.path().join("source.zip");
            let snapshot = create_snapshot(root.path()).err();
            let zipped = export_zip(root.path(), &artifact);
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(snapshot.unwrap().contains("cannot open source file"));
            assert!(zipped.unwrap_err().contains("cannot write ZIP artifact"));
            assert!(!artifact.exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_source_file_that_cannot_be_opened_fails_the_zip_writer() {
        // An inventoried file the archive writer cannot open fails the
        // archive rather than leaving a hole in it.
        let found = Inventory {
            files: vec![(
                "app.txt".into(),
                PathBuf::from(crate::test_support::UNREADABLE_FILE),
                0o100644,
            )],
            ..Default::default()
        };
        let mut archive = std::io::Cursor::new(Vec::new());
        let err = write_zip(&mut archive, found).unwrap_err().to_string();
        assert!(err.contains("cannot open source file"), "{err}");
        assert!(err.contains("Permission denied"), "{err}");
    }

    #[test]
    fn the_archive_stops_at_its_depth_and_entry_and_byte_bounds() {
        let root = tempfile::tempdir().unwrap();
        let mut deep = root.path().to_path_buf();
        for _ in 0..=MAX_DEPTH {
            deep.push("nested");
        }
        fs::create_dir_all(&deep).unwrap();
        assert_eq!(
            inventory_error(root.path()),
            "source exceeds archive depth limit (32)"
        );

        // The 30,000-entry and 256 MiB ceilings are driven from an
        // already-spent inventory. Materializing either in full would
        // dominate the suite without exercising anything the running
        // totals do not already decide.
        let source = tempfile::tempdir().unwrap();
        fs::write(source.path().join("app.txt"), b"fixed").unwrap();
        let mut counted_out = Inventory {
            entries: MAX_ENTRIES,
            ..Default::default()
        };
        assert_eq!(
            walk(source.path(), "", 0, &mut counted_out).unwrap_err(),
            "source exceeds archive entry limit (30000)"
        );
        let mut spent = Inventory {
            bytes: MAX_BYTES,
            ..Default::default()
        };
        assert_eq!(
            walk(source.path(), "", 0, &mut spent).unwrap_err(),
            "source exceeds archive byte limit (256 MiB)"
        );
    }

    #[test]
    fn a_filename_no_portable_consumer_can_extract_fails_the_archive() {
        let root = tempfile::tempdir().unwrap();
        // `walk` reports the path it refused, so an operator can find it.
        fs::write(root.path().join("trailing."), b"fixed").unwrap();
        assert!(inventory_error(root.path())
            .contains("source filename is not portable or safe for ZIP: \"trailing.\""));
    }

    #[cfg(unix)]
    #[test]
    fn a_special_file_fails_the_archive_rather_than_being_silently_dropped() {
        let root = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(root.path().join("pipe"))
            .status()
            .expect("mkfifo is a POSIX utility");
        assert!(status.success());
        assert_eq!(
            inventory_error(root.path()),
            "source contains an unsupported special file: pipe"
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_a_regular_readable_file_is_opened_for_the_archive() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        assert!(open_regular(&root.path().join("missing"))
            .unwrap_err()
            .contains("cannot inspect source file"));
        assert_eq!(
            open_regular(root.path()).unwrap_err(),
            "source changed to a non-regular file"
        );
        let target = root.path().join("app.txt");
        fs::write(&target, b"fixed").unwrap();
        symlink(&target, root.path().join("alias")).unwrap();
        assert_eq!(
            open_regular(&root.path().join("alias")).unwrap_err(),
            "source changed to a non-regular file"
        );
        // A regular file root cannot open either (a chmod 000 file would
        // not stop root).
        #[cfg(target_os = "linux")]
        assert!(
            open_regular(Path::new(crate::test_support::UNREADABLE_FILE))
                .unwrap_err()
                .contains("cannot open source file")
        );
    }

    #[test]
    fn a_zip_destination_directory_that_does_not_exist_is_reported() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.txt"), b"fixed").unwrap();
        let out = tempfile::tempdir().unwrap();
        assert!(
            export_zip(root.path(), &out.path().join("missing/source.zip"))
                .unwrap_err()
                .contains("cannot stage ZIP artifact")
        );
    }
}
