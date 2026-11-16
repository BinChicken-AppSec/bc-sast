use std::path::{Path, PathBuf};

use appsec_enrich::AppInfo;
use appsec_model::{AppProfile, Reach};

pub const CONTEXT_FILE: &str = "context.yaml";

pub mod corroborate;
pub mod extract;
pub mod supplied;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub reference: String,
    pub retrieved: Option<String>,
    pub modified: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeploymentContext {
    pub profile: AppProfile,
    pub app: AppInfo,
    pub exposure: Exposure,
    pub data: Vec<DataClass>,
    pub availability: Option<Availability>,
    pub reaches: Vec<Reach>,
    pub reached_by: Vec<Reach>,
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    NetworkPath(String),
    InsideScanTarget {
        dir: PathBuf,
        target: PathBuf,
    },
    Unreadable {
        path: PathBuf,
        reason: String,
    },
    Malformed {
        path: PathBuf,
        reason: String,
    },
    UnknownKey {
        path: PathBuf,
        key: String,
    },
    MissingFact {
        path: PathBuf,
        key: &'static str,
    },
    BadValue {
        path: PathBuf,
        key: &'static str,
        got: String,
        allowed: &'static str,
    },
    WrongType {
        path: PathBuf,
        key: String,
        expected: &'static str,
    },
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkPath(p) => write!(f, "refusing a network path: {p}"),
            Self::InsideScanTarget { dir, target } => write!(
                f,
                "refusing deployment context {} resolved inside scan target {}: the \
                 scanned repository would be setting its own severity ratings (set \
                 BC_ALLOW_IN_TARGET_CONTEXT to override)",
                dir.display(),
                target.display()
            ),
            Self::Unreadable { path, reason } => {
                write!(f, "cannot read {}: {reason}", path.display())
            }
            Self::Malformed { path, reason } => {
                write!(f, "{} is not a context mapping: {reason}", path.display())
            }
            Self::UnknownKey { path, key } => write!(
                f,
                "{} has an unrecognized key {key:?}; a misspelled fact would \
                 silently read as false, so it is refused",
                path.display()
            ),
            Self::MissingFact { path, key } => write!(
                f,
                "{} does not state {key}; every exposure and sensitivity fact \
                 must be explicit, because an omitted one would read as false",
                path.display()
            ),
            Self::BadValue {
                path,
                key,
                got,
                allowed,
            } => write!(
                f,
                "{} has {key}: {got:?}, which is not recognized; expected {allowed}",
                path.display()
            ),
            Self::WrongType {
                path,
                key,
                expected,
            } => write!(
                f,
                "{} has {key} as the wrong type; expected {expected}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ContextError {}

const KEYS: [&str; 7] = [
    "id",
    "name",
    "exposure",
    "data",
    "availability",
    "topology",
    "sources",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    Internet,
    Partner,
    Internal,
    Isolated,
}

impl Exposure {
    fn as_str(self) -> &'static str {
        match self {
            Self::Internet => "internet",
            Self::Partner => "partner",
            Self::Internal => "internal",
            Self::Isolated => "isolated",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "internet" => Some(Self::Internet),
            "partner" => Some(Self::Partner),
            "internal" => Some(Self::Internal),
            "isolated" => Some(Self::Isolated),
            _ => None,
        }
    }

    fn externally_facing(self) -> bool {
        matches!(self, Self::Internet | Self::Partner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClass {
    Pan,
    Pci,
    Pii,
    Phi,
    Secrets,
    None,
}

impl DataClass {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "pan" => Some(Self::Pan),
            "pci" => Some(Self::Pci),
            "pii" => Some(Self::Pii),
            "phi" => Some(Self::Phi),
            "secrets" => Some(Self::Secrets),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

const REACH_KINDS: [&str; 7] = [
    "database",
    "queue",
    "metadata",
    "service",
    "internet",
    "filesystem",
    "other",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    High,
    Normal,
    Low,
}

impl Availability {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "high" => Some(Self::High),
            "normal" => Some(Self::Normal),
            "low" => Some(Self::Low),
            _ => None,
        }
    }

    fn requirement(self) -> char {
        match self {
            Self::High => 'H',
            Self::Normal => 'M',
            Self::Low => 'L',
        }
    }
}

pub fn load(
    dir: &Path,
    scan_target_root: &Path,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<DeploymentContext>, ContextError> {
    if appsec_pathjail::is_network_path(&dir.to_string_lossy()) {
        return Err(ContextError::NetworkPath(dir.display().to_string()));
    }
    if appsec_pathjail::is_within(scan_target_root, dir)
        && getenv("BC_ALLOW_IN_TARGET_CONTEXT").is_none_or(|v| v.trim().is_empty())
    {
        return Err(ContextError::InsideScanTarget {
            dir: dir.to_path_buf(),
            target: scan_target_root.to_path_buf(),
        });
    }
    let path = dir.join(CONTEXT_FILE);
    if !path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| ContextError::Unreadable {
        path: path.clone(),
        reason: e.to_string(),
    })?;
    parse(&text, &path).map(Some)
}

pub fn parse(text: &str, path: &Path) -> Result<DeploymentContext, ContextError> {
    let value = appsec_yaml::parse_strict(text).map_err(|e| ContextError::Malformed {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let map = value.as_object().ok_or_else(|| ContextError::Malformed {
        path: path.to_path_buf(),
        reason: "the top level is not a mapping".to_string(),
    })?;
    for key in map.keys() {
        if !KEYS.contains(&key.as_str()) {
            return Err(ContextError::UnknownKey {
                path: path.to_path_buf(),
                key: key.clone(),
            });
        }
    }

    let str_at = |key: &'static str| -> Result<Option<&str>, ContextError> {
        match map.get(key) {
            None => Ok(None),
            Some(v) => v.as_str().map(Some).ok_or(ContextError::WrongType {
                path: path.to_path_buf(),
                key: key.to_string(),
                expected: "a string",
            }),
        }
    };

    let exposure_raw = str_at("exposure")?.ok_or(ContextError::MissingFact {
        path: path.to_path_buf(),
        key: "exposure",
    })?;
    let exposure = Exposure::parse(exposure_raw).ok_or_else(|| ContextError::BadValue {
        path: path.to_path_buf(),
        key: "exposure",
        got: exposure_raw.to_string(),
        allowed: "internet, partner, internal, isolated",
    })?;

    let data = parse_data(map.get("data"), path)?;
    let availability = match str_at("availability")? {
        None => None,
        Some(raw) => Some(
            Availability::parse(raw).ok_or_else(|| ContextError::BadValue {
                path: path.to_path_buf(),
                key: "availability",
                got: raw.to_string(),
                allowed: "high, normal, low",
            })?,
        ),
    };

    let (reaches, reached_by) = parse_topology(map.get("topology"), path)?;
    let id = str_at("id")?.unwrap_or_default().to_string();
    let name = str_at("name")?.unwrap_or_default().to_string();
    let sources = parse_sources(map.get("sources"), path)?;
    let origin = if sources.is_empty() {
        format!("context:{}", path.display())
    } else {
        format!("context:{}", sources[0].reference)
    };

    let has = |c: DataClass| data.contains(&c);
    let externally_facing = exposure.externally_facing();
    let pci_scoped = has(DataClass::Pci) || has(DataClass::Pan);
    let processes_pan = has(DataClass::Pan);
    let pii = has(DataClass::Pii) || has(DataClass::Phi);

    Ok(DeploymentContext {
        profile: AppProfile {
            application_id: id.clone(),
            name: name.clone(),
            externally_facing,
            pci_scoped,
            processes_pan,
            pii,
            source: origin.clone(),
            exposure: exposure_raw.to_string(),
            reaches: reaches.clone(),
            reached_by: reached_by.clone(),
        },
        app: AppInfo {
            id,
            name,
            externally_facing,
            pci_scoped,
            processes_pan,
            pii,
            ext_raw: None,
            pci_raw: None,
            pan_raw: None,
            pii_raw: None,
            parent_app_id: None,
            source: origin,
            availability: availability.map(Availability::requirement),
        },
        exposure,
        data,
        availability,
        reaches,
        reached_by,
        sources,
    })
}

fn parse_data(
    value: Option<&serde_json::Value>,
    path: &Path,
) -> Result<Vec<DataClass>, ContextError> {
    let value = value.ok_or(ContextError::MissingFact {
        path: path.to_path_buf(),
        key: "data",
    })?;
    let list = value.as_array().ok_or_else(|| ContextError::WrongType {
        path: path.to_path_buf(),
        key: "data".to_string(),
        expected: "a list",
    })?;
    if list.is_empty() {
        return Err(ContextError::BadValue {
            path: path.to_path_buf(),
            key: "data",
            got: "an empty list".to_string(),
            allowed: "at least one of pan, pci, pii, phi, secrets, none",
        });
    }
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let raw = entry.as_str().ok_or_else(|| ContextError::WrongType {
            path: path.to_path_buf(),
            key: "data".to_string(),
            expected: "a list of strings",
        })?;
        let class = DataClass::parse(raw).ok_or_else(|| ContextError::BadValue {
            path: path.to_path_buf(),
            key: "data",
            got: raw.to_string(),
            allowed: "pan, pci, pii, phi, secrets, none",
        })?;
        if !out.contains(&class) {
            out.push(class);
        }
    }
    if out.contains(&DataClass::None) && out.len() > 1 {
        return Err(ContextError::BadValue {
            path: path.to_path_buf(),
            key: "data",
            got: "none alongside another class".to_string(),
            allowed: "none on its own, or any combination of the others",
        });
    }
    Ok(out)
}

fn parse_topology(
    value: Option<&serde_json::Value>,
    path: &Path,
) -> Result<(Vec<Reach>, Vec<Reach>), ContextError> {
    let Some(value) = value else {
        return Ok((Vec::new(), Vec::new()));
    };
    let map = value.as_object().ok_or_else(|| ContextError::WrongType {
        path: path.to_path_buf(),
        key: "topology".to_string(),
        expected: "a mapping",
    })?;
    for key in map.keys() {
        if !matches!(key.as_str(), "reaches" | "reached_by") {
            return Err(ContextError::UnknownKey {
                path: path.to_path_buf(),
                key: format!("topology.{key}"),
            });
        }
    }
    Ok((
        parse_reaches(map.get("reaches"), "topology.reaches", path)?,
        parse_reaches(map.get("reached_by"), "topology.reached_by", path)?,
    ))
}

fn parse_reaches(
    value: Option<&serde_json::Value>,
    key: &'static str,
    path: &Path,
) -> Result<Vec<Reach>, ContextError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = value.as_array().ok_or_else(|| ContextError::WrongType {
        path: path.to_path_buf(),
        key: key.to_string(),
        expected: "a list",
    })?;
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        if let Some(name) = entry.as_str() {
            out.push(Reach {
                name: name.to_string(),
                kind: "other".to_string(),
                authenticated: None,
            });
            continue;
        }
        let m = entry.as_object().ok_or_else(|| ContextError::WrongType {
            path: path.to_path_buf(),
            key: key.to_string(),
            expected: "a list of strings or mappings",
        })?;
        for k in m.keys() {
            if !matches!(k.as_str(), "name" | "kind" | "authenticated") {
                return Err(ContextError::UnknownKey {
                    path: path.to_path_buf(),
                    key: format!("{key}[].{k}"),
                });
            }
        }
        let name = m
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or(ContextError::MissingFact {
                path: path.to_path_buf(),
                key: "topology entry name",
            })?
            .to_string();
        let kind = match m.get("kind") {
            None => "other".to_string(),
            Some(v) => {
                let raw = v.as_str().ok_or_else(|| ContextError::WrongType {
                    path: path.to_path_buf(),
                    key: format!("{key}[].kind"),
                    expected: "a string",
                })?;
                if !REACH_KINDS.contains(&raw) {
                    return Err(ContextError::BadValue {
                        path: path.to_path_buf(),
                        key: "topology kind",
                        got: raw.to_string(),
                        allowed: "database, queue, metadata, service, internet, filesystem, other",
                    });
                }
                raw.to_string()
            }
        };
        let authenticated = match m.get("authenticated") {
            None => None,
            Some(v) => Some(v.as_bool().ok_or_else(|| ContextError::WrongType {
                path: path.to_path_buf(),
                key: format!("{key}[].authenticated"),
                expected: "a boolean",
            })?),
        };
        out.push(Reach {
            name,
            kind,
            authenticated,
        });
    }
    Ok(out)
}

fn parse_sources(
    value: Option<&serde_json::Value>,
    path: &Path,
) -> Result<Vec<Source>, ContextError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = value.as_array().ok_or_else(|| ContextError::WrongType {
        path: path.to_path_buf(),
        key: "sources".to_string(),
        expected: "a list",
    })?;
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        if let Some(s) = entry.as_str() {
            out.push(Source {
                reference: s.to_string(),
                retrieved: None,
                modified: None,
            });
            continue;
        }
        let m = entry.as_object().ok_or_else(|| ContextError::WrongType {
            path: path.to_path_buf(),
            key: "sources".to_string(),
            expected: "a list of strings or mappings",
        })?;
        for key in m.keys() {
            if !matches!(key.as_str(), "reference" | "retrieved" | "modified") {
                return Err(ContextError::UnknownKey {
                    path: path.to_path_buf(),
                    key: format!("sources[].{key}"),
                });
            }
        }
        let field =
            |key: &str| -> Result<Option<String>, ContextError> {
                match m.get(key) {
                    None => Ok(None),
                    Some(v) => v.as_str().map(|s| Some(s.to_owned())).ok_or_else(|| {
                        ContextError::WrongType {
                            path: path.to_path_buf(),
                            key: format!("sources[].{key}"),
                            expected: "a string",
                        }
                    }),
                }
            };
        out.push(Source {
            reference: field("reference")?.unwrap_or_default(),
            retrieved: field("retrieved")?,
            modified: field("modified")?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "\
id: payments-api
name: Payments API
exposure: internet
data: [pan, pii]
availability: high
";

    fn at(name: &str) -> PathBuf {
        PathBuf::from(name)
    }

    fn elsewhere() -> PathBuf {
        PathBuf::from("/nonexistent-scan-target")
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn wrong_type(e: &ContextError) -> Option<(String, &'static str)> {
        match e {
            ContextError::WrongType { key, expected, .. } => Some((key.clone(), expected)),
            _ => None,
        }
    }

    fn missing_fact(e: &ContextError) -> Option<&'static str> {
        match e {
            ContextError::MissingFact { key, .. } => Some(*key),
            _ => None,
        }
    }

    fn unknown_key(e: &ContextError) -> Option<String> {
        match e {
            ContextError::UnknownKey { key, .. } => Some(key.clone()),
            _ => None,
        }
    }

    fn bad_value(e: &ContextError) -> Option<(&'static str, String)> {
        match e {
            ContextError::BadValue { key, got, .. } => Some((*key, got.clone())),
            _ => None,
        }
    }

    #[test]
    fn the_richer_shape_derives_the_legacy_one() {
        let c = parse(FULL, &at("context.yaml")).expect("parses");
        assert_eq!(c.exposure, Exposure::Internet);
        assert_eq!(c.data, vec![DataClass::Pan, DataClass::Pii]);
        assert_eq!(c.availability, Some(Availability::High));
        assert!(c.profile.externally_facing);
        assert!(c.profile.pci_scoped, "a PAN is in PCI scope");
        assert!(c.profile.processes_pan);
        assert!(c.profile.pii);
        assert_eq!(c.app.availability, Some('H'));
    }

    #[test]
    fn partner_reach_is_external_but_internal_and_isolated_are_not() {
        for (word, external) in [
            ("internet", true),
            ("partner", true),
            ("internal", false),
            ("isolated", false),
        ] {
            let y = FULL.replace("exposure: internet", &format!("exposure: {word}"));
            let c = parse(&y, &at("c.yaml")).expect("parses");
            assert_eq!(c.profile.externally_facing, external, "{word}");
        }
    }

    #[test]
    fn each_data_class_maps_to_the_right_requirement() {
        for (word, pci, pan, pii) in [
            ("pan", true, true, false),
            ("pci", true, false, false),
            ("pii", false, false, true),
            ("phi", false, false, true),
            ("secrets", false, false, false),
            ("none", false, false, false),
        ] {
            let y = FULL.replace("data: [pan, pii]", &format!("data: [{word}]"));
            let c = parse(&y, &at("c.yaml")).expect("parses");
            assert_eq!(
                (c.profile.pci_scoped, c.profile.processes_pan, c.profile.pii),
                (pci, pan, pii),
                "{word}"
            );
        }
    }

    #[test]
    fn the_facts_change_the_environmental_score() {
        let base = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let score = |yaml: &str| {
            let a = parse(yaml, &at("c.yaml")).expect("parses").app;
            appsec_cvss::environmental(
                Some(base),
                if a.externally_facing { 'N' } else { 'L' },
                a.cr(),
                a.ir(),
                a.ar(),
            )
            .expect("scores")
            .1
        };
        let hi = score(FULL);
        let lo = score("exposure: internal\ndata: [none]\navailability: low\n");
        assert!(hi > lo, "exposed+PCI must out-rate internal: {hi} vs {lo}");
    }

    #[test]
    fn availability_now_reaches_the_vector_and_defaults_as_before() {
        for (word, want) in [("high", 'H'), ("normal", 'M'), ("low", 'L')] {
            let y = FULL.replace("availability: high", &format!("availability: {word}"));
            assert_eq!(parse(&y, &at("c.yaml")).expect("parses").app.ar(), want);
        }
        let bare: String = FULL
            .lines()
            .filter(|l| !l.starts_with("availability:"))
            .map(|l| format!("{l}\n"))
            .collect();
        let c = parse(&bare, &at("c.yaml")).expect("parses");
        assert_eq!(c.availability, None);
        assert_eq!(c.app.ar(), 'M');
    }

    #[test]
    fn exposure_and_data_are_required_because_omitting_them_under_rates() {
        for key in ["exposure", "data"] {
            let y: String = FULL
                .lines()
                .filter(|l| !l.starts_with(&format!("{key}:")))
                .map(|l| format!("{l}\n"))
                .collect();
            let err = parse(&y, &at("c.yaml")).expect_err("refused");
            assert_eq!(missing_fact(&err), Some(key), "{err:?}");
            assert!(err.to_string().contains("must be explicit"));
        }
    }

    #[test]
    fn an_unrecognized_value_names_what_is_allowed() {
        let y = FULL.replace("exposure: internet", "exposure: public");
        let err = parse(&y, &at("c.yaml")).expect_err("refused");
        assert_eq!(bad_value(&err), Some(("exposure", "public".to_string())));
        assert!(err
            .to_string()
            .contains("internet, partner, internal, isolated"));

        let y = FULL.replace("data: [pan, pii]", "data: [cardholder]");
        let err = parse(&y, &at("c.yaml")).expect_err("refused");
        assert_eq!(bad_value(&err), Some(("data", "cardholder".to_string())));

        let y = FULL.replace("availability: high", "availability: critical");
        let err = parse(&y, &at("c.yaml")).expect_err("refused");
        assert_eq!(bad_value(&err).map(|(k, _)| k), Some("availability"));
    }

    #[test]
    fn data_must_say_something_and_none_must_stand_alone() {
        let y = FULL.replace("data: [pan, pii]", "data: []");
        let err = parse(&y, &at("c.yaml")).expect_err("refused");
        assert_eq!(bad_value(&err).map(|(k, _)| k), Some("data"));
        assert!(err.to_string().contains("at least one of"));

        let y = FULL.replace("data: [pan, pii]", "data: [none, pii]");
        let err = parse(&y, &at("c.yaml")).expect_err("refused");
        assert!(err.to_string().contains("none on its own"), "{err}");
    }

    #[test]
    fn a_repeated_data_class_is_accepted_once() {
        let y = FULL.replace("data: [pan, pii]", "data: [pii, pii, pan]");
        let c = parse(&y, &at("c.yaml")).expect("parses");
        assert_eq!(c.data, vec![DataClass::Pii, DataClass::Pan]);
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let y = format!("{FULL}exposre: internet\n");
        let err = parse(&y, &at("c.yaml")).expect_err("refused");
        assert_eq!(unknown_key(&err).as_deref(), Some("exposre"));
        assert!(err.to_string().contains("silently read as false"));
    }

    #[test]
    fn wrongly_shaped_values_are_refused() {
        for (y, key, expected) in [
            (
                FULL.replace("exposure: internet", "exposure: 7"),
                "exposure",
                "a string",
            ),
            (
                FULL.replace("data: [pan, pii]", "data: pan"),
                "data",
                "a list",
            ),
            (
                FULL.replace("data: [pan, pii]", "data: [7]"),
                "data",
                "a list of strings",
            ),
            (FULL.replace("id: payments-api", "id: 7"), "id", "a string"),
        ] {
            let err = parse(&y, &at("c.yaml")).expect_err("refused");
            assert_eq!(
                wrong_type(&err),
                Some((key.to_string(), expected)),
                "{err:?}"
            );
        }
    }

    #[test]
    fn identity_is_optional() {
        let bare: String = FULL
            .lines()
            .filter(|l| !l.starts_with("id:") && !l.starts_with("name:"))
            .map(|l| format!("{l}\n"))
            .collect();
        let c = parse(&bare, &at("c.yaml")).expect("parses");
        assert_eq!(c.profile.application_id, "");
        assert_eq!(c.profile.name, "");
    }

    #[test]
    fn a_non_mapping_document_is_refused() {
        let err = parse("- just\n- a list\n", &at("c.yaml")).expect_err("refused");
        assert!(matches!(err, ContextError::Malformed { .. }), "{err:?}");
        assert!(err.to_string().contains("not a context mapping"));
    }

    #[test]
    fn unparseable_yaml_is_refused() {
        let err = parse("a: [unterminated\n", &at("c.yaml")).expect_err("refused");
        assert!(matches!(err, ContextError::Malformed { .. }), "{err:?}");
    }

    #[test]
    fn sources_accept_a_bare_string_or_a_mapping() {
        let y = format!(
            "{FULL}sources:\n  - docs/arch.md\n  - reference: https://wiki/x\n    \
             retrieved: 2026-11-12\n    modified: 2024-02-01\n  - reference: docs/only.md\n"
        );
        let c = parse(&y, &at("c.yaml")).expect("parses");
        assert_eq!(c.sources.len(), 3);
        assert_eq!(c.sources[0].reference, "docs/arch.md");
        assert_eq!(c.sources[0].retrieved, None);
        assert_eq!(c.sources[1].retrieved.as_deref(), Some("2026-11-12"));
        assert_eq!(c.sources[1].modified.as_deref(), Some("2024-02-01"));
        assert_eq!(c.sources[2].retrieved, None);
        assert_eq!(c.profile.source, "context:docs/arch.md");
        assert_eq!(c.app.source, "context:docs/arch.md");
    }

    #[test]
    fn malformed_sources_are_refused() {
        for (y, want) in [
            (format!("{FULL}sources: nope\n"), "a list"),
            (
                format!("{FULL}sources:\n  - 7\n"),
                "a list of strings or mappings",
            ),
            (format!("{FULL}sources:\n  - reference: 7\n"), "a string"),
        ] {
            let err = parse(&y, &at("c.yaml")).expect_err("refused");
            assert_eq!(wrong_type(&err).map(|(_, e)| e), Some(want), "{err:?}");
        }
        let err = parse(&format!("{FULL}sources:\n  - refrence: x\n"), &at("c.yaml"))
            .expect_err("refused");
        assert_eq!(unknown_key(&err).as_deref(), Some("sources[].refrence"));
    }

    #[test]
    fn an_absent_file_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load(dir.path(), &elsewhere(), &no_env)
            .expect("no error")
            .is_none());
    }

    #[test]
    fn a_present_file_loads_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CONTEXT_FILE), FULL).expect("write");
        let c = load(dir.path(), &elsewhere(), &no_env)
            .expect("loads")
            .expect("present");
        assert_eq!(c.exposure, Exposure::Internet);
    }

    #[test]
    fn a_present_but_broken_file_is_an_error_not_a_skip() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CONTEXT_FILE), "id: x\n").expect("write");
        assert!(load(dir.path(), &elsewhere(), &no_env).is_err());
    }

    #[test]
    fn a_network_path_is_refused_before_touching_the_filesystem() {
        let err = load(Path::new(r"\\attacker\share"), &elsewhere(), &no_env).expect_err("refused");
        assert!(matches!(err, ContextError::NetworkPath(_)), "{err:?}");
        assert!(err.to_string().contains("refusing a network path"));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(CONTEXT_FILE);
        std::fs::write(&path, FULL).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let unenforceable = std::fs::read_to_string(&path).is_ok();
        let outcome = load(dir.path(), &elsewhere(), &no_env);
        assert!(
            unenforceable || matches!(outcome, Err(ContextError::Unreadable { .. })),
            "{outcome:?}"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    #[test]
    fn every_error_renders() {
        let p = at("c.yaml");
        let cases = [
            (
                ContextError::Unreadable {
                    path: p.clone(),
                    reason: "denied".into(),
                },
                "cannot read",
            ),
            (ContextError::NetworkPath("x".into()), "network path"),
            (
                ContextError::Malformed {
                    path: p.clone(),
                    reason: "bad".into(),
                },
                "not a context mapping",
            ),
            (
                ContextError::UnknownKey {
                    path: p.clone(),
                    key: "k".into(),
                },
                "unrecognized key",
            ),
            (
                ContextError::MissingFact {
                    path: p.clone(),
                    key: "data",
                },
                "must be explicit",
            ),
            (
                ContextError::WrongType {
                    path: p.clone(),
                    key: "data".into(),
                    expected: "a list",
                },
                "expected a list",
            ),
            (
                ContextError::BadValue {
                    path: p,
                    key: "exposure",
                    got: "public".into(),
                    allowed: "internet",
                },
                "not recognized",
            ),
        ];
        for (e, want) in cases {
            assert!(e.to_string().contains(want), "{e:?} -> {}", e);
        }
    }

    #[test]
    fn each_accessor_matches_its_own_variant_and_no_other() {
        let p = at("c.yaml");
        let wt = ContextError::WrongType {
            path: p.clone(),
            key: "k".into(),
            expected: "a boolean",
        };
        let mf = ContextError::MissingFact {
            path: p.clone(),
            key: "data",
        };
        let uk = ContextError::UnknownKey {
            path: p.clone(),
            key: "nope".into(),
        };
        let bv = ContextError::BadValue {
            path: p,
            key: "exposure",
            got: "public".into(),
            allowed: "internet",
        };
        assert_eq!(wrong_type(&wt), Some(("k".into(), "a boolean")));
        assert_eq!(wrong_type(&mf), None);
        assert_eq!(missing_fact(&mf), Some("data"));
        assert_eq!(missing_fact(&uk), None);
        assert_eq!(unknown_key(&uk).as_deref(), Some("nope"));
        assert_eq!(unknown_key(&bv), None);
        assert_eq!(bad_value(&bv), Some(("exposure", "public".to_string())));
        assert_eq!(bad_value(&wt), None);
    }

    const TOPO: &str = "\
topology:
  reached_by:
    - name: edge-gateway
      kind: service
      authenticated: true
  reaches:
    - name: payments-db
      kind: database
    - instance-metadata
";

    #[test]
    fn topology_is_parsed_and_reaches_the_profile() {
        let c = parse(&format!("{FULL}{TOPO}"), &at("c.yaml")).expect("parses");
        assert_eq!(c.reached_by.len(), 1);
        assert_eq!(c.reached_by[0].name, "edge-gateway");
        assert_eq!(c.reached_by[0].kind, "service");
        assert_eq!(c.reached_by[0].authenticated, Some(true));
        assert_eq!(c.reaches.len(), 2);
        assert_eq!(c.reaches[0].kind, "database");
        assert_eq!(c.reaches[1].name, "instance-metadata");
        assert_eq!(c.reaches[1].kind, "other");
        assert_eq!(c.reaches[1].authenticated, None);
        assert_eq!(c.profile.reaches.len(), 2);
        assert_eq!(c.profile.reached_by.len(), 1);
        assert_eq!(c.profile.exposure, "internet");
    }

    #[test]
    fn topology_is_optional() {
        let c = parse(FULL, &at("c.yaml")).expect("parses");
        assert!(c.reaches.is_empty());
        assert!(c.reached_by.is_empty());
        assert_eq!(c.profile.exposure, "internet");
    }

    #[test]
    fn one_direction_alone_is_enough() {
        let y = format!("{FULL}topology:\n  reaches:\n    - name: db\n      kind: database\n");
        let c = parse(&y, &at("c.yaml")).expect("parses");
        assert_eq!(c.reaches.len(), 1);
        assert!(c.reached_by.is_empty());

        let y = format!("{FULL}topology:\n  reached_by:\n    - edge\n");
        let c = parse(&y, &at("c.yaml")).expect("parses");
        assert!(c.reaches.is_empty());
        assert_eq!(c.reached_by.len(), 1);
    }

    #[test]
    fn an_unrecognized_reach_kind_is_refused() {
        let y = format!("{FULL}topology:\n  reaches:\n    - name: x\n      kind: smtp\n");
        let err = parse(&y, &at("c.yaml")).expect_err("refused");
        assert_eq!(
            bad_value(&err),
            Some(("topology kind", "smtp".to_string())),
            "{err:?}"
        );
        assert!(err.to_string().contains("metadata"));
    }

    #[test]
    fn a_reach_without_a_name_is_refused() {
        let y = format!("{FULL}topology:\n  reaches:\n    - kind: database\n");
        let err = parse(&y, &at("c.yaml")).expect_err("refused");
        assert_eq!(missing_fact(&err), Some("topology entry name"), "{err:?}");
    }

    #[test]
    fn malformed_topology_is_refused() {
        for (y, key, expected) in [
            (format!("{FULL}topology: nope\n"), "topology", "a mapping"),
            (
                format!("{FULL}topology:\n  reaches: nope\n"),
                "topology.reaches",
                "a list",
            ),
            (
                format!("{FULL}topology:\n  reaches:\n    - 7\n"),
                "topology.reaches",
                "a list of strings or mappings",
            ),
            (
                format!("{FULL}topology:\n  reaches:\n    - name: x\n      kind: 7\n"),
                "topology.reaches[].kind",
                "a string",
            ),
            (
                format!(
                    "{FULL}topology:\n  reaches:\n    - name: x\n      authenticated: yes-ish\n"
                ),
                "topology.reaches[].authenticated",
                "a boolean",
            ),
        ] {
            let err = parse(&y, &at("c.yaml")).expect_err("refused");
            assert_eq!(
                wrong_type(&err),
                Some((key.to_string(), expected)),
                "{err:?}"
            );
        }
        for (y, key) in [
            (
                format!("{FULL}topology:\n  reachs: []\n"),
                "topology.reachs",
            ),
            (
                format!("{FULL}topology:\n  reaches:\n    - name: x\n      authed: true\n"),
                "topology.reaches[].authed",
            ),
        ] {
            let err = parse(&y, &at("c.yaml")).expect_err("refused");
            assert_eq!(unknown_key(&err).as_deref(), Some(key), "{err:?}");
        }
    }

    #[test]
    fn a_context_dir_inside_the_scan_target_is_refused() {
        let target = tempfile::tempdir().expect("tempdir");
        let dir = target.path().join("security");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join(CONTEXT_FILE), FULL).expect("write");
        let err = load(&dir, target.path(), &no_env).expect_err("refused");
        assert!(
            matches!(err, ContextError::InsideScanTarget { .. }),
            "{err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("setting its own severity ratings"), "{msg}");
        assert!(msg.contains("BC_ALLOW_IN_TARGET_CONTEXT"), "{msg}");
    }

    #[test]
    fn the_in_target_refusal_can_be_overridden_deliberately() {
        let target = tempfile::tempdir().expect("tempdir");
        let dir = target.path().join("security");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join(CONTEXT_FILE), FULL).expect("write");
        let allow = |k: &str| (k == "BC_ALLOW_IN_TARGET_CONTEXT").then(|| "1".to_string());
        let c = load(&dir, target.path(), &allow)
            .expect("allowed")
            .expect("present");
        assert_eq!(c.exposure, Exposure::Internet);
    }

    #[test]
    fn an_empty_override_does_not_count_as_set() {
        let target = tempfile::tempdir().expect("tempdir");
        let dir = target.path().join("security");
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::write(dir.join(CONTEXT_FILE), FULL).expect("write");
        let blank = |k: &str| (k == "BC_ALLOW_IN_TARGET_CONTEXT").then(|| "  ".to_string());
        assert!(matches!(
            load(&dir, target.path(), &blank),
            Err(ContextError::InsideScanTarget { .. })
        ));
    }

    #[test]
    fn errors_are_std_errors() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&ContextError::NetworkPath("x".into()));
    }
}
