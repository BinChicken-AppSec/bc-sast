use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Checkmarx,
    Semgrep,
    Snyk,
    Aikido,
    Sonatype,
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProduct {
    Sast,
    Dependency,
    Secret,
    Other,
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSource {
    Api,
    File,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderNativeIds {
    pub issue_id: Option<String>,
    pub match_based_id: Option<String>,
    pub similarity_id: Option<String>,
    pub attack_vector_id: Option<String>,
    pub asset_finding_id: Option<String>,
    pub group_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default)]
pub struct ComponentRef {
    pub name: String,
    pub version: String,
    pub purl: Option<String>,
    pub cves: Vec<String>,
    pub fixed_in: Vec<String>,
    pub dependency_path: Vec<String>,
    pub direct: Option<bool>,
}

impl ComponentRef {
    pub fn coordinate(&self) -> String {
        match (self.name.is_empty(), self.version.is_empty()) {
            (true, _) => String::new(),
            (false, true) => self.name.clone(),
            (false, false) => format!("{}@{}", self.name, self.version),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.purl.is_none() && self.cves.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderOrigin {
    pub provider: ProviderKind,
    pub product: ProviderProduct,
    pub source: ProviderSource,
    pub native_ids: ProviderNativeIds,
    pub tenant_id: Option<String>,
    pub project_id: Option<String>,
    pub repository_id: Option<String>,
    pub repository_name: Option<String>,
    pub git_ref: Option<String>,
    pub revision: Option<String>,
    pub scan_id: Option<String>,
    pub state: Option<String>,
    pub severity: Option<String>,
}

#[cfg(test)]
mod component_ref_tests {
    use super::*;

    #[test]
    fn a_coordinate_needs_a_name() {
        let c = ComponentRef {
            version: "1.0".to_string(),
            ..ComponentRef::default()
        };
        assert_eq!(
            c.coordinate(),
            "",
            "a version with no package names nothing"
        );
    }

    #[test]
    fn a_name_without_a_version_is_still_a_coordinate() {
        let c = ComponentRef {
            name: "lodash".to_string(),
            ..ComponentRef::default()
        };
        assert_eq!(c.coordinate(), "lodash");
    }

    #[test]
    fn a_name_and_version_join_with_an_at_sign() {
        let c = ComponentRef {
            name: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ..ComponentRef::default()
        };
        assert_eq!(c.coordinate(), "lodash@4.17.15");
    }

    #[test]
    fn a_component_is_empty_only_without_a_name_a_purl_and_a_cve() {
        assert!(ComponentRef::default().is_empty());
        assert!(!ComponentRef {
            name: "x".to_string(),
            ..ComponentRef::default()
        }
        .is_empty());
        assert!(!ComponentRef {
            purl: Some("pkg:npm/x@1".to_string()),
            ..ComponentRef::default()
        }
        .is_empty());
        assert!(
            !ComponentRef {
                cves: vec!["CVE-1".to_string()],
                ..ComponentRef::default()
            }
            .is_empty(),
            "a bare CVE id is still something the verifier should see"
        );
    }
}
