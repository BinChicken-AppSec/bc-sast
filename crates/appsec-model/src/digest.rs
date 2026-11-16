use crate::{Finding, ProviderKind, ProviderProduct};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_DIGEST_HOTSPOTS: usize = 10;
pub const MAX_DIGEST_DEPENDENCIES: usize = 25;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderHotspot {
    pub path: String,
    pub count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderDependencyAlert {
    pub component: String,
    pub title: String,
    pub severity: String,
    pub vendor: String,
    pub cves: Vec<String>,
    pub fixed_in: Vec<String>,
    pub direct: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProviderDigest {
    pub total: usize,
    pub by_vendor: BTreeMap<String, usize>,
    pub by_product: BTreeMap<String, usize>,
    pub by_severity: BTreeMap<String, usize>,
    pub by_class: BTreeMap<String, usize>,
    pub hotspots: Vec<ProviderHotspot>,
    pub dependencies: Vec<ProviderDependencyAlert>,
    pub dependencies_truncated: bool,
}

pub fn vendor_name(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Checkmarx => "checkmarx",
        ProviderKind::Semgrep => "semgrep",
        ProviderKind::Snyk => "snyk",
        ProviderKind::Aikido => "aikido",
        ProviderKind::Sonatype => "sonatype",
        ProviderKind::Unknown => "unknown",
    }
}

pub fn product_name(product: ProviderProduct) -> &'static str {
    match product {
        ProviderProduct::Sast => "sast",
        ProviderProduct::Dependency => "dependency",
        ProviderProduct::Secret => "secret",
        ProviderProduct::Other => "other",
        ProviderProduct::Unknown => "unknown",
    }
}

pub fn severity_rank(severity: &str) -> u8 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

fn top_level_dir(path: &str) -> String {
    let trimmed = path.trim_start_matches("./").trim_start_matches('/');
    match trimmed.split_once('/') {
        Some((head, _)) if !head.is_empty() => head.to_string(),
        _ => "(repo root)".to_string(),
    }
}

fn bump(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

impl ProviderDigest {
    pub fn of(findings: &[Finding]) -> Self {
        let mut digest = ProviderDigest {
            total: findings.len(),
            ..ProviderDigest::default()
        };
        let mut hotspots: BTreeMap<String, usize> = BTreeMap::new();
        let mut deps: BTreeMap<(String, String), ProviderDependencyAlert> = BTreeMap::new();

        for finding in findings {
            bump(&mut digest.by_class, finding.vuln_class.as_str());
            let mut is_dependency = false;
            if finding.provider_origins.is_empty() {
                bump(&mut digest.by_vendor, "unknown");
                bump(&mut digest.by_product, "unknown");
                bump(&mut digest.by_severity, "unknown");
            }
            for origin in &finding.provider_origins {
                bump(&mut digest.by_vendor, vendor_name(origin.provider));
                bump(&mut digest.by_product, product_name(origin.product));
                let severity = origin
                    .severity
                    .as_deref()
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "unknown".to_string());
                bump(&mut digest.by_severity, &severity);
                if origin.product == ProviderProduct::Dependency {
                    is_dependency = true;
                    let component = finding
                        .component
                        .as_ref()
                        .map(|c| c.coordinate())
                        .filter(|c| !c.is_empty())
                        .unwrap_or_else(|| finding.file.clone());
                    let key = (component.clone(), finding.title.clone());
                    deps.entry(key).or_insert_with(|| ProviderDependencyAlert {
                        component,
                        title: finding.title.clone(),
                        severity,
                        vendor: vendor_name(origin.provider).to_string(),
                        cves: finding
                            .component
                            .as_ref()
                            .map(|c| c.cves.clone())
                            .unwrap_or_default(),
                        fixed_in: finding
                            .component
                            .as_ref()
                            .map(|c| c.fixed_in.clone())
                            .unwrap_or_default(),
                        direct: finding.component.as_ref().and_then(|c| c.direct),
                    });
                }
            }
            if !is_dependency && !finding.file.trim().is_empty() {
                *hotspots.entry(top_level_dir(&finding.file)).or_insert(0) += 1;
            }
        }

        let mut ranked: Vec<ProviderHotspot> = hotspots
            .into_iter()
            .map(|(path, count)| ProviderHotspot { path, count })
            .collect();
        ranked.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.path.cmp(&b.path)));
        ranked.truncate(MAX_DIGEST_HOTSPOTS);
        digest.hotspots = ranked;

        let mut alerts: Vec<ProviderDependencyAlert> = deps.into_values().collect();
        alerts.sort_by(|a, b| {
            severity_rank(&a.severity)
                .cmp(&severity_rank(&b.severity))
                .then_with(|| a.component.cmp(&b.component))
                .then_with(|| a.title.cmp(&b.title))
        });
        digest.dependencies_truncated = alerts.len() > MAX_DIGEST_DEPENDENCIES;
        alerts.truncate(MAX_DIGEST_DEPENDENCIES);
        digest.dependencies = alerts;

        digest
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderOrigin, VulnClass};

    fn finding(file: &str, class: VulnClass, origins: Vec<ProviderOrigin>) -> Finding {
        let mut built: Finding = serde_json::from_value(serde_json::json!({
            "chunk_id": "c",
            "file": file,
            "line_start": 1,
            "line_end": 1,
            "vuln_class": class,
            "title": "t",
            "description": "",
            "code_snippet": "",
            "confidence": 0.5,
        }))
        .expect("a minimal finding deserialises");
        built.provider_origins = origins;
        built
    }

    fn origin(
        provider: ProviderKind,
        product: ProviderProduct,
        severity: Option<&str>,
    ) -> ProviderOrigin {
        ProviderOrigin {
            provider,
            product,
            severity: severity.map(|s| s.to_string()),
            ..ProviderOrigin::default()
        }
    }

    #[test]
    fn a_digest_of_nothing_is_empty() {
        let digest = ProviderDigest::of(&[]);
        assert!(digest.is_empty());
        assert_eq!(digest.total, 0);
        assert!(digest.hotspots.is_empty());
        assert!(digest.dependencies.is_empty());
        assert!(!digest.dependencies_truncated);
    }

    #[test]
    fn counts_are_grouped_by_tool_kind_severity_and_class() {
        let findings = vec![
            finding(
                "src/a.py",
                VulnClass::Injection,
                vec![origin(
                    ProviderKind::Semgrep,
                    ProviderProduct::Sast,
                    Some("high"),
                )],
            ),
            finding(
                "src/b.py",
                VulnClass::Injection,
                vec![origin(
                    ProviderKind::Checkmarx,
                    ProviderProduct::Sast,
                    Some("HIGH"),
                )],
            ),
            finding(
                "lib/c.py",
                VulnClass::InfoLeak,
                vec![origin(
                    ProviderKind::Semgrep,
                    ProviderProduct::Sast,
                    Some("low"),
                )],
            ),
        ];
        let digest = ProviderDigest::of(&findings);
        assert_eq!(digest.total, 3);
        assert_eq!(digest.by_vendor["semgrep"], 2);
        assert_eq!(digest.by_vendor["checkmarx"], 1);
        assert_eq!(digest.by_product["sast"], 3);
        assert_eq!(
            digest.by_severity["high"], 2,
            "severity is normalised to lower case before counting"
        );
        assert_eq!(digest.by_severity["low"], 1);
        assert_eq!(digest.by_class[VulnClass::Injection.as_str()], 2);
        assert_eq!(digest.by_class[VulnClass::InfoLeak.as_str()], 1);
    }

    #[test]
    fn hotspots_rank_top_level_directories_by_count() {
        let mut findings = Vec::new();
        for i in 0..3 {
            findings.push(finding(
                &format!("src/{i}.py"),
                VulnClass::Injection,
                vec![origin(ProviderKind::Semgrep, ProviderProduct::Sast, None)],
            ));
        }
        findings.push(finding(
            "lib/x.py",
            VulnClass::Injection,
            vec![origin(ProviderKind::Semgrep, ProviderProduct::Sast, None)],
        ));
        findings.push(finding(
            "main.py",
            VulnClass::Injection,
            vec![origin(ProviderKind::Semgrep, ProviderProduct::Sast, None)],
        ));
        let digest = ProviderDigest::of(&findings);
        assert_eq!(digest.hotspots[0].path, "src");
        assert_eq!(digest.hotspots[0].count, 3);
        assert!(
            digest
                .hotspots
                .iter()
                .any(|h| h.path == "(repo root)" && h.count == 1),
            "a file with no directory is still placed"
        );
    }

    #[test]
    fn a_missing_severity_or_origin_is_counted_as_unknown() {
        let findings = vec![
            finding("a.py", VulnClass::Other, Vec::new()),
            finding(
                "b.py",
                VulnClass::Other,
                vec![origin(
                    ProviderKind::Snyk,
                    ProviderProduct::Sast,
                    Some("  "),
                )],
            ),
        ];
        let digest = ProviderDigest::of(&findings);
        assert_eq!(digest.by_vendor["unknown"], 1);
        assert_eq!(digest.by_product["unknown"], 1);
        assert_eq!(
            digest.by_severity["unknown"], 2,
            "a blank severity is unknown, not an empty bucket"
        );
    }

    #[test]
    fn dependency_findings_become_alerts_and_never_hotspots() {
        let findings = vec![finding(
            "lodash@4.17.15",
            VulnClass::Other,
            vec![origin(
                ProviderKind::Snyk,
                ProviderProduct::Dependency,
                Some("critical"),
            )],
        )];
        let digest = ProviderDigest::of(&findings);
        assert_eq!(digest.dependencies.len(), 1);
        assert_eq!(digest.dependencies[0].component, "lodash@4.17.15");
        assert_eq!(digest.dependencies[0].vendor, "snyk");
        assert_eq!(digest.dependencies[0].severity, "critical");
        assert!(
            digest.hotspots.is_empty(),
            "a package coordinate is not a repository path and must not be ranked as one"
        );
    }

    #[test]
    fn alerts_are_ordered_by_severity_then_component() {
        let findings = vec![
            finding(
                "zeta@1",
                VulnClass::Other,
                vec![origin(
                    ProviderKind::Snyk,
                    ProviderProduct::Dependency,
                    Some("low"),
                )],
            ),
            finding(
                "beta@1",
                VulnClass::Other,
                vec![origin(
                    ProviderKind::Snyk,
                    ProviderProduct::Dependency,
                    Some("critical"),
                )],
            ),
            finding(
                "alpha@1",
                VulnClass::Other,
                vec![origin(
                    ProviderKind::Snyk,
                    ProviderProduct::Dependency,
                    Some("critical"),
                )],
            ),
        ];
        let digest = ProviderDigest::of(&findings);
        let order: Vec<&str> = digest
            .dependencies
            .iter()
            .map(|d| d.component.as_str())
            .collect();
        assert_eq!(order, vec!["alpha@1", "beta@1", "zeta@1"]);
    }

    #[test]
    fn the_alert_list_is_capped_and_says_so() {
        let findings: Vec<Finding> = (0..MAX_DIGEST_DEPENDENCIES + 5)
            .map(|i| {
                finding(
                    &format!("pkg{i:03}@1"),
                    VulnClass::Other,
                    vec![origin(
                        ProviderKind::Sonatype,
                        ProviderProduct::Dependency,
                        Some("high"),
                    )],
                )
            })
            .collect();
        let digest = ProviderDigest::of(&findings);
        assert_eq!(digest.dependencies.len(), MAX_DIGEST_DEPENDENCIES);
        assert!(
            digest.dependencies_truncated,
            "a capped list that does not say it was capped reads as complete"
        );
        assert_eq!(
            digest.total,
            MAX_DIGEST_DEPENDENCIES + 5,
            "the total still counts everything that was ingested"
        );
    }

    #[test]
    fn the_same_component_reported_twice_is_listed_once() {
        let dupe = || {
            finding(
                "lodash@4.17.15",
                VulnClass::Other,
                vec![origin(
                    ProviderKind::Snyk,
                    ProviderProduct::Dependency,
                    Some("high"),
                )],
            )
        };
        let digest = ProviderDigest::of(&[dupe(), dupe()]);
        assert_eq!(digest.dependencies.len(), 1);
        assert_eq!(digest.total, 2);
    }

    #[test]
    fn a_digest_survives_a_json_round_trip() {
        let digest = ProviderDigest::of(&[finding(
            "src/a.py",
            VulnClass::Injection,
            vec![origin(
                ProviderKind::Semgrep,
                ProviderProduct::Sast,
                Some("high"),
            )],
        )]);
        let text = serde_json::to_string(&digest).expect("serialises");
        let back: ProviderDigest = serde_json::from_str(&text).expect("deserialises");
        assert_eq!(back, digest);
    }

    #[test]
    fn every_vendor_and_product_has_a_name() {
        for (kind, name) in [
            (ProviderKind::Checkmarx, "checkmarx"),
            (ProviderKind::Semgrep, "semgrep"),
            (ProviderKind::Snyk, "snyk"),
            (ProviderKind::Aikido, "aikido"),
            (ProviderKind::Sonatype, "sonatype"),
            (ProviderKind::Unknown, "unknown"),
        ] {
            assert_eq!(vendor_name(kind), name);
        }
        for (product, name) in [
            (ProviderProduct::Sast, "sast"),
            (ProviderProduct::Dependency, "dependency"),
            (ProviderProduct::Secret, "secret"),
            (ProviderProduct::Other, "other"),
            (ProviderProduct::Unknown, "unknown"),
        ] {
            assert_eq!(product_name(product), name);
        }
    }

    #[test]
    fn two_issues_in_one_component_are_ordered_by_title() {
        let alert = |title: &str| {
            let mut f = finding(
                "lodash@4.17.15",
                VulnClass::Other,
                vec![origin(
                    ProviderKind::Snyk,
                    ProviderProduct::Dependency,
                    Some("high"),
                )],
            );
            f.title = title.to_string();
            f
        };
        let digest =
            ProviderDigest::of(&[alert("Prototype Pollution"), alert("Command Injection")]);
        let titles: Vec<&str> = digest
            .dependencies
            .iter()
            .map(|d| d.title.as_str())
            .collect();
        assert_eq!(
            titles,
            vec!["Command Injection", "Prototype Pollution"],
            "same component and severity still needs a stable order, or two scans disagree"
        );
    }

    #[test]
    fn a_secret_finding_is_counted_but_is_not_a_dependency() {
        let digest = ProviderDigest::of(&[finding(
            "src/config.py",
            VulnClass::InfoLeak,
            vec![origin(
                ProviderKind::Aikido,
                ProviderProduct::Secret,
                Some("high"),
            )],
        )]);
        assert_eq!(digest.by_product["secret"], 1);
        assert_eq!(digest.by_vendor["aikido"], 1);
        assert!(digest.dependencies.is_empty());
        assert_eq!(digest.hotspots[0].path, "src");
    }

    fn with_component(file: &str, component: crate::ComponentRef) -> Finding {
        let mut f = finding(
            file,
            VulnClass::Other,
            vec![origin(
                ProviderKind::Snyk,
                ProviderProduct::Dependency,
                Some("high"),
            )],
        );
        f.component = Some(component);
        f
    }

    #[test]
    fn an_alert_is_keyed_on_the_component_not_the_file_string() {
        let digest = ProviderDigest::of(&[with_component(
            "package-lock.json",
            crate::ComponentRef {
                name: "lodash".to_string(),
                version: "4.17.15".to_string(),
                ..crate::ComponentRef::default()
            },
        )]);
        assert_eq!(
            digest.dependencies[0].component, "lodash@4.17.15",
            "the manifest path is not the component the advisory is about"
        );
    }

    #[test]
    fn the_alert_carries_the_cves_the_fix_and_whether_it_is_direct() {
        let digest = ProviderDigest::of(&[with_component(
            "package-lock.json",
            crate::ComponentRef {
                name: "lodash".to_string(),
                version: "4.17.15".to_string(),
                cves: vec!["CVE-2020-8203".to_string()],
                fixed_in: vec!["4.17.19".to_string()],
                direct: Some(false),
                ..crate::ComponentRef::default()
            },
        )]);
        let alert = &digest.dependencies[0];
        assert_eq!(alert.cves, vec!["CVE-2020-8203"]);
        assert_eq!(alert.fixed_in, vec!["4.17.19"]);
        assert_eq!(alert.direct, Some(false));
    }

    #[test]
    fn a_component_without_a_coordinate_falls_back_to_the_file() {
        let digest = ProviderDigest::of(&[with_component(
            "package-lock.json",
            crate::ComponentRef::default(),
        )]);
        assert_eq!(digest.dependencies[0].component, "package-lock.json");
    }

    #[test]
    fn two_cves_in_one_component_stay_separate_alerts_when_titled_apart() {
        let mut a = with_component(
            "p",
            crate::ComponentRef {
                name: "lodash".to_string(),
                version: "4.17.15".to_string(),
                ..crate::ComponentRef::default()
            },
        );
        a.title = "Prototype Pollution".to_string();
        let mut b = a.clone();
        b.title = "Command Injection".to_string();
        let digest = ProviderDigest::of(&[a, b]);
        assert_eq!(digest.dependencies.len(), 2);
    }

    #[test]
    fn severity_rank_orders_critical_first_and_unrecognised_last() {
        assert!(severity_rank("critical") < severity_rank("high"));
        assert!(severity_rank("high") < severity_rank("medium"));
        assert!(severity_rank("info") < severity_rank("banana"));
        assert_eq!(severity_rank("CRITICAL"), severity_rank("critical"));
    }
}
