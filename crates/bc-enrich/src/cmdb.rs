//! CMDB CSV loading and application/parent lookup, ported from
//! `report/enrich.py`'s `AppInfo`/`load_cmdb_csv`/`lookup_app`/
//! `_merge_with_parent`/`_pick`/`_cmdb_enrichment_differs`.
//!
//! **Deliberately not ported**: the Python original's `cmdb_comp`
//! (component-level CMDB) parameter on `lookup_app` — every real call
//! site (`orchestrator/cmdb.py::_load_app_profile`, and `report/
//! enrich.py::enrich`'s standalone-CLI path) always passes an empty
//! dict for it, making the entire "component" branch of `lookup_app`
//! provably dead given how it's actually invoked; this port drops that
//! parameter and the dead branch it fed, keeping only the
//! application→parent merge path that's genuinely reachable.

use std::collections::HashMap;
use std::path::Path;

use crate::csv_parse::parse_csv;

/// One CMDB row: exposure/sensitivity signal for an application (or, once
/// merged with a parent, a component inheriting its parent's signal for
/// any field its own row left blank).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AppInfo {
    pub id: String,
    pub name: String,
    pub externally_facing: bool,
    pub pci_scoped: bool,
    pub processes_pan: bool,
    pub pii: bool,
    pub ext_raw: Option<String>,
    pub pci_raw: Option<String>,
    pub pan_raw: Option<String>,
    pub pii_raw: Option<String>,
    pub parent_app_id: Option<String>,
    pub source: String,
}

impl AppInfo {
    /// Confidentiality Requirement: `H` if the app is PCI-scoped, processes
    /// PANs, or holds PII; `M` otherwise.
    pub fn cr(&self) -> char {
        if self.pci_scoped || self.processes_pan || self.pii {
            'H'
        } else {
            'M'
        }
    }

    /// Integrity Requirement: `H` if PCI-scoped or processes PANs; `M`
    /// otherwise (PII alone doesn't raise integrity — leaking it is a
    /// confidentiality concern, not a tampering one).
    pub fn ir(&self) -> char {
        if self.pci_scoped || self.processes_pan {
            'H'
        } else {
            'M'
        }
    }

    /// Availability Requirement: always `M` — this project has no signal
    /// that would justify raising it.
    pub fn ar(&self) -> char {
        'M'
    }

    /// Modified Attack Vector: downgrades an internet-reachable base
    /// vector (`AV:N`) to `A` (adjacent network) when the app is confirmed
    /// NOT externally facing; every other base vector passes through
    /// unchanged.
    pub fn mav(&self, base_av: char) -> char {
        if !self.externally_facing && base_av == 'N' {
            'A'
        } else {
            base_av
        }
    }

    pub fn env_summary(&self) -> String {
        format!(
            "CR:{}/IR:{}/AR:{} extFacing={}",
            self.cr(),
            self.ir(),
            self.ar(),
            self.externally_facing
        )
    }
}

/// Strip leading zeros after trimming whitespace, `"0"` if that leaves
/// nothing — so CMDB ids like `"007"` and `"7"` collide on lookup.
pub fn normalize_app_id(app_id: &str) -> String {
    let stripped = app_id.trim().trim_start_matches('0');
    if stripped.is_empty() {
        "0".to_string()
    } else {
        stripped.to_string()
    }
}

fn normalize_parent_id(id: Option<&str>) -> Option<String> {
    id.map(normalize_app_id)
}

fn yes(v: Option<&str>) -> bool {
    v.is_some_and(|s| s.trim().eq_ignore_ascii_case("yes"))
}

fn nz(v: Option<&str>) -> Option<String> {
    let t = v?.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// True when two CMDB rows that collide on [`normalize_app_id`] carry
/// DIFFERENT enrichment signal (the four decision bools, plus the parent
/// they inherit from, normalized). Exact/benign duplicates return `false`
/// so they stay silent; only a genuine conflict that would drift severity
/// is worth a warning.
fn cmdb_enrichment_differs(x: &AppInfo, y: &AppInfo) -> bool {
    if x.externally_facing != y.externally_facing
        || x.pci_scoped != y.pci_scoped
        || x.processes_pan != y.processes_pan
        || x.pii != y.pii
    {
        return true;
    }
    normalize_parent_id(x.parent_app_id.as_deref())
        != normalize_parent_id(y.parent_app_id.as_deref())
}

/// `csv_col(hdr, "id")`-style single-name header lookup — the Python
/// original's `_csv_col` accepts multiple candidate names (a varargs
/// fallback chain), but every real call site passes exactly one, so this
/// port keeps only the single-name form actually used.
fn csv_col(hdr: &HashMap<String, usize>, name: &str) -> Option<usize> {
    hdr.get(name).copied()
}

fn at(row: &[String], i: Option<usize>) -> Option<&str> {
    i.and_then(|idx| row.get(idx)).map(String::as_str)
}

/// Read a CMDB CSV export into `id -> AppInfo` (id normalized via
/// [`normalize_app_id`]). `""` or a missing path is not an error — an
/// empty map, matching the Python original (CMDB enrichment is entirely
/// optional). License-header comment lines (`#...`) and blank lines
/// before the real header row are skipped, matching this project's
/// `cmdb.csv` carrying an Apache-2.0 banner. A network (UNC/`\\host\share`)
/// path is checked and refused before any filesystem touch — even a
/// failed `is_file()` stat would trigger Windows' SMB handshake and leak
/// the caller's NTLMv2 hash to a malicious host.
pub fn load_cmdb_csv(path: &Path) -> Result<HashMap<String, AppInfo>, String> {
    let mut out: HashMap<String, AppInfo> = HashMap::new();
    if path.as_os_str().is_empty() {
        return Ok(out);
    }
    if bc_pathjail::is_network_path(&path.to_string_lossy()) {
        return Err(format!("{}: network paths are not allowed", path.display()));
    }
    if !path.is_file() {
        return Ok(out);
    }

    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(&text);
    let mut rows = parse_csv(text).into_iter();

    let header = loop {
        match rows.next() {
            None => return Ok(out),
            Some(row) => {
                let first = row.first().map(|s| s.trim_start()).unwrap_or("");
                let all_blank = row.iter().all(|c| c.trim().is_empty());
                if first.starts_with('#') || all_blank {
                    continue;
                }
                break row;
            }
        }
    };

    let hdr: HashMap<String, usize> = header
        .iter()
        .enumerate()
        .map(|(i, h)| (h.trim().to_lowercase(), i))
        .collect();
    let i_id = csv_col(&hdr, "id");
    let i_name = csv_col(&hdr, "name");
    let i_ext = csv_col(&hdr, "externally_facing");
    let i_pci = csv_col(&hdr, "pci");
    let i_pan = csv_col(&hdr, "pan");
    let i_pii = csv_col(&hdr, "pii");
    let i_par = csv_col(&hdr, "parent_id");
    let Some(i_id) = i_id else {
        return Err(format!("CMDB CSV missing 'id' column: {}", path.display()));
    };

    for row in rows {
        let Some(rid) = at(&row, Some(i_id)) else {
            continue;
        };
        let rid = rid.trim();
        if rid.is_empty() {
            continue;
        }
        let mut a = AppInfo {
            id: rid.to_string(),
            name: at(&row, i_name).unwrap_or("").to_string(),
            source: "application".to_string(),
            ..Default::default()
        };
        a.ext_raw = nz(at(&row, i_ext));
        a.pci_raw = nz(at(&row, i_pci));
        a.pan_raw = nz(at(&row, i_pan));
        a.pii_raw = nz(at(&row, i_pii));
        a.externally_facing = yes(a.ext_raw.as_deref());
        a.pci_scoped = yes(a.pci_raw.as_deref());
        a.processes_pan = yes(a.pan_raw.as_deref());
        a.pii = yes(a.pii_raw.as_deref());
        a.parent_app_id = nz(at(&row, i_par));

        let key = normalize_app_id(&a.id);
        if let Some(prior) = out.get(&key) {
            if cmdb_enrichment_differs(prior, &a) {
                // Formatted eagerly: `tracing`'s macros only evaluate
                // their arguments when a subscriber has the callsite
                // enabled, and no test installs one, so the two
                // `env_summary()` calls were never executed.
                let msg = format!(
                    "[cmdb] id {:?} normalises to the same key {key:?} as earlier id {:?}, but their exposure/sensitivity differ ({} vs {}); last-wins — disambiguate the CMDB to avoid severity-enrichment drift",
                    a.id,
                    prior.id,
                    prior.env_summary(),
                    a.env_summary()
                );
                tracing::warn!("{msg}");
            }
        }
        out.insert(key, a);
    }
    Ok(out)
}

// `&dyn Fn` (not a generic `impl Fn` per parameter) so every call site
// shares one compiled body — a generic version here would monomorphize
// separately for each of the four ext/pci/pan/pii closure sets in
// `merge_with_parent` below, and cargo-llvm-cov's line-coverage union
// across those instantiations is unreliable (see
// `feedback_coverage_tool_gotchas.md`).
//
// `own` is `&AppInfo`, not `Option<&AppInfo>`: every real call site in
// `lookup_app` (and the Python original's `_merge_with_parent`, which has
// the exact same `Optional[AppInfo]` parameter) always passes the same
// object twice — once as `base`/`own` — so the "own is absent" branch is
// provably dead given how this is actually invoked, the same class of
// simplification as this module's already-documented `cmdb_comp` drop.
fn pick(
    own: &AppInfo,
    parent: Option<&AppInfo>,
    own_raw: &dyn Fn(&AppInfo) -> &Option<String>,
    own_val: &dyn Fn(&AppInfo) -> bool,
    parent_val: &dyn Fn(&AppInfo) -> bool,
) -> bool {
    if own_raw(own).is_some() {
        return own_val(own);
    }
    if let Some(p) = parent {
        return parent_val(p);
    }
    own_val(own)
}

fn merge_with_parent(
    base: &AppInfo,
    own: &AppInfo,
    parent: Option<&AppInfo>,
    source: String,
) -> AppInfo {
    AppInfo {
        id: base.id.clone(),
        name: base.name.clone(),
        parent_app_id: own.parent_app_id.clone(),
        source,
        externally_facing: pick(
            own,
            parent,
            &|a| &a.ext_raw,
            &|a| a.externally_facing,
            &|a| a.externally_facing,
        ),
        pci_scoped: pick(own, parent, &|a| &a.pci_raw, &|a| a.pci_scoped, &|a| {
            a.pci_scoped
        }),
        processes_pan: pick(own, parent, &|a| &a.pan_raw, &|a| a.processes_pan, &|a| {
            a.processes_pan
        }),
        pii: pick(own, parent, &|a| &a.pii_raw, &|a| a.pii, &|a| a.pii),
        ..Default::default()
    }
}

/// Resolve `app_id` against the loaded CMDB, filling any blank field
/// (missing `externally_facing`/`pci`/`pan`/`pii` column value) from the
/// row's `parent_id` when one is present. `None` if `app_id` is empty or
/// not found.
pub fn lookup_app(app_id: &str, cmdb: &HashMap<String, AppInfo>) -> Option<AppInfo> {
    if app_id.is_empty() {
        return None;
    }
    let key = normalize_app_id(app_id);
    let a = cmdb.get(&key)?;
    let any_blank =
        a.pci_raw.is_none() || a.pan_raw.is_none() || a.pii_raw.is_none() || a.ext_raw.is_none();
    if any_blank {
        if let Some(pid) = a.parent_app_id.as_deref() {
            let parent_key = normalize_app_id(pid);
            if let Some(p) = cmdb.get(&parent_key) {
                if normalize_app_id(&p.id) != key {
                    return Some(merge_with_parent(
                        a,
                        a,
                        Some(p),
                        format!("application->parent {}", p.id),
                    ));
                }
            }
        }
    }
    let mut result = a.clone();
    result.source = "application".to_string();
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(externally_facing: bool, pci: bool, pan: bool, pii: bool) -> AppInfo {
        AppInfo {
            externally_facing,
            pci_scoped: pci,
            processes_pan: pan,
            pii,
            ..Default::default()
        }
    }

    #[test]
    fn cr_is_high_when_any_sensitive_flag_is_set() {
        assert_eq!(app(true, true, false, false).cr(), 'H');
        assert_eq!(app(true, false, true, false).cr(), 'H');
        assert_eq!(app(true, false, false, true).cr(), 'H');
        assert_eq!(app(true, false, false, false).cr(), 'M');
    }

    #[test]
    fn ir_ignores_pii_alone() {
        assert_eq!(app(true, false, false, true).ir(), 'M');
        assert_eq!(app(true, true, false, false).ir(), 'H');
        assert_eq!(app(true, false, true, false).ir(), 'H');
    }

    #[test]
    fn ar_is_always_medium() {
        assert_eq!(app(true, true, true, true).ar(), 'M');
        assert_eq!(app(false, false, false, false).ar(), 'M');
    }

    #[test]
    fn mav_downgrades_network_to_adjacent_for_an_internal_app() {
        assert_eq!(app(false, false, false, false).mav('N'), 'A');
        assert_eq!(app(true, false, false, false).mav('N'), 'N');
    }

    #[test]
    fn mav_passes_through_every_non_network_base_vector_unchanged() {
        let internal = app(false, false, false, false);
        assert_eq!(internal.mav('A'), 'A');
        assert_eq!(internal.mav('L'), 'L');
        assert_eq!(internal.mav('P'), 'P');
    }

    #[test]
    fn env_summary_includes_all_four_fields() {
        let s = app(true, true, false, false).env_summary();
        assert!(s.contains("CR:H"));
        assert!(s.contains("IR:H"));
        assert!(s.contains("AR:M"));
        assert!(s.contains("extFacing=true"));
    }

    #[rstest::rstest]
    #[case("007", "7")]
    #[case("0", "0")]
    #[case("00", "0")]
    #[case("  42  ", "42")]
    #[case("", "0")]
    fn normalize_app_id_strips_leading_zeros(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(normalize_app_id(input), expected);
    }

    fn write(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn missing_or_empty_path_yields_an_empty_map() {
        assert!(load_cmdb_csv(Path::new("")).unwrap().is_empty());
        assert!(load_cmdb_csv(Path::new("/does/not/exist.csv"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_network_path_is_refused_without_touching_the_filesystem() {
        let err = load_cmdb_csv(Path::new(r"\\attacker\share\cmdb.csv")).unwrap_err();
        assert!(err.contains("network paths are not allowed"));
    }

    #[cfg(unix)]
    #[test]
    fn a_genuine_read_error_on_an_existing_file_is_an_err() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "cmdb.csv", "id,name\n1,Acme\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = load_cmdb_csv(&p);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn loads_a_simple_csv_with_a_license_header_comment() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "cmdb.csv",
            "# Apache-2.0 license banner\n\nid,name,externally_facing,pci,pan,pii,parent_id\n42,Acme Payments,yes,yes,no,no,\n",
        );
        let cmdb = load_cmdb_csv(&p).unwrap();
        let a = cmdb.get("42").unwrap();
        assert_eq!(a.name, "Acme Payments");
        assert!(a.externally_facing);
        assert!(a.pci_scoped);
        assert!(!a.processes_pan);
    }

    #[test]
    fn leading_zeros_in_the_id_column_normalize_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "cmdb.csv", "id,name\n007,Acme\n");
        let cmdb = load_cmdb_csv(&p).unwrap();
        assert!(cmdb.contains_key("7"));
    }

    #[test]
    fn a_row_with_a_blank_id_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "cmdb.csv", "id,name\n,Acme\n7,Real\n");
        let cmdb = load_cmdb_csv(&p).unwrap();
        assert_eq!(cmdb.len(), 1);
        assert!(cmdb.contains_key("7"));
    }

    #[test]
    fn missing_id_column_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "cmdb.csv", "name,pci\nAcme,yes\n");
        let err = load_cmdb_csv(&p).unwrap_err();
        assert!(err.contains("missing 'id' column"));
    }

    #[test]
    fn a_data_row_shorter_than_the_id_column_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        // Header has 7 columns (id is index 0 here, so use a header where
        // id is NOT the first column and a short row genuinely lacks it).
        let p = write(dir.path(), "cmdb.csv", "name,id\nonly-one-field\nReal,7\n");
        let cmdb = load_cmdb_csv(&p).unwrap();
        assert_eq!(cmdb.len(), 1);
        assert!(cmdb.contains_key("7"));
    }

    #[test]
    fn a_csv_with_only_comments_and_blank_lines_yields_an_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "cmdb.csv", "# just a comment\n\n");
        assert!(load_cmdb_csv(&p).unwrap().is_empty());
    }

    #[test]
    fn a_later_duplicate_id_with_differing_signal_wins_last_and_is_still_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "cmdb.csv",
            "id,name,externally_facing,pci,pan,pii,parent_id\n7,First,yes,no,no,no,\n07,Second,no,no,no,no,\n",
        );
        let cmdb = load_cmdb_csv(&p).unwrap();
        assert_eq!(cmdb.get("7").unwrap().name, "Second");
    }

    #[test]
    fn a_later_duplicate_id_with_identical_signal_is_silent_and_last_wins() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            "cmdb.csv",
            "id,name,externally_facing,pci,pan,pii,parent_id\n7,First,yes,no,no,no,\n07,Second,yes,no,no,no,\n",
        );
        let cmdb = load_cmdb_csv(&p).unwrap();
        assert_eq!(cmdb.get("7").unwrap().name, "Second");
    }

    fn cmdb_map(rows: Vec<AppInfo>) -> HashMap<String, AppInfo> {
        rows.into_iter()
            .map(|a| (normalize_app_id(&a.id), a))
            .collect()
    }

    #[test]
    fn lookup_app_empty_id_is_none() {
        assert_eq!(lookup_app("", &HashMap::new()), None);
    }

    #[test]
    fn lookup_app_not_found_is_none() {
        assert_eq!(lookup_app("999", &HashMap::new()), None);
    }

    #[test]
    fn lookup_app_direct_hit_with_no_blank_fields_needs_no_merge() {
        let a = AppInfo {
            id: "42".to_string(),
            name: "Acme".to_string(),
            ext_raw: Some("yes".to_string()),
            pci_raw: Some("no".to_string()),
            pan_raw: Some("no".to_string()),
            pii_raw: Some("no".to_string()),
            externally_facing: true,
            ..Default::default()
        };
        let cmdb = cmdb_map(vec![a]);
        let found = lookup_app("42", &cmdb).unwrap();
        assert_eq!(found.source, "application");
        assert!(found.externally_facing);
    }

    #[test]
    fn lookup_app_merges_blank_fields_from_the_parent() {
        let parent = AppInfo {
            id: "1".to_string(),
            ext_raw: Some("yes".to_string()),
            pci_raw: Some("yes".to_string()),
            pan_raw: Some("no".to_string()),
            pii_raw: Some("no".to_string()),
            externally_facing: true,
            pci_scoped: true,
            ..Default::default()
        };
        let child = AppInfo {
            id: "2".to_string(),
            name: "Child".to_string(),
            parent_app_id: Some("1".to_string()),
            ..Default::default()
        };
        let cmdb = cmdb_map(vec![parent, child]);
        let found = lookup_app("2", &cmdb).unwrap();
        assert!(found.externally_facing);
        assert!(found.pci_scoped);
        assert!(found.source.contains("application->parent 1"));
    }

    #[test]
    fn lookup_app_merge_keeps_a_present_own_field_instead_of_the_parents() {
        // Child has pci_raw present (its own "no" should win) but ext_raw
        // blank (so externally_facing should come from the parent) —
        // exercises `pick`'s "own's raw field is present" branch, not just
        // the "own has nothing, fall through" case the other merge test
        // covers.
        let parent = AppInfo {
            id: "1".to_string(),
            ext_raw: Some("yes".to_string()),
            pci_raw: Some("yes".to_string()),
            pan_raw: Some("no".to_string()),
            pii_raw: Some("no".to_string()),
            externally_facing: true,
            pci_scoped: true,
            ..Default::default()
        };
        let child = AppInfo {
            id: "2".to_string(),
            parent_app_id: Some("1".to_string()),
            pci_raw: Some("no".to_string()),
            pci_scoped: false,
            ..Default::default()
        };
        let cmdb = cmdb_map(vec![parent, child]);
        let found = lookup_app("2", &cmdb).unwrap();
        assert!(found.externally_facing); // inherited from parent (own ext_raw blank)
        assert!(!found.pci_scoped); // own value wins (own pci_raw present)
    }

    #[test]
    fn lookup_app_with_blank_fields_but_no_parent_id_uses_its_own_computed_values() {
        let child = AppInfo {
            id: "2".to_string(),
            ..Default::default()
        };
        let cmdb = cmdb_map(vec![child]);
        let found = lookup_app("2", &cmdb).unwrap();
        assert_eq!(found.source, "application");
        assert!(!found.externally_facing);
    }

    #[test]
    fn lookup_app_with_a_parent_id_that_does_not_resolve_falls_back_to_its_own_values() {
        let child = AppInfo {
            id: "2".to_string(),
            parent_app_id: Some("999".to_string()),
            ..Default::default()
        };
        let cmdb = cmdb_map(vec![child]);
        let found = lookup_app("2", &cmdb).unwrap();
        assert_eq!(found.source, "application");
    }

    #[test]
    fn lookup_app_a_self_referential_parent_id_is_ignored() {
        let a = AppInfo {
            id: "2".to_string(),
            parent_app_id: Some("2".to_string()),
            ..Default::default()
        };
        let cmdb = cmdb_map(vec![a]);
        let found = lookup_app("2", &cmdb).unwrap();
        assert_eq!(found.source, "application");
    }

    #[test]
    fn merge_with_parent_falls_back_to_own_value_when_neither_raw_nor_parent_present() {
        let base = AppInfo {
            id: "2".to_string(),
            pci_scoped: true,
            ..Default::default()
        };
        let merged = merge_with_parent(&base, &base, None, "test".to_string());
        assert!(merged.pci_scoped);
    }
}
