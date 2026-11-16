use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoKeySource {
    Explicit,
    Environment,
    Derived,
}

impl RepoKeySource {
    pub fn as_str(self) -> &'static str {
        match self {
            RepoKeySource::Explicit => "explicit",
            RepoKeySource::Environment => "environment",
            RepoKeySource::Derived => "derived",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoKey {
    pub value: String,
    pub source: RepoKeySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RepoIdentity {
    #[serde(default)]
    pub key: Option<RepoKey>,
    #[serde(default)]
    pub origin_display: Option<String>,
    #[serde(default)]
    pub subtree: String,
    #[serde(default)]
    pub root_commit: Option<String>,
    #[serde(default)]
    pub root_commit_verified: bool,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub merge_base: Option<String>,
    #[serde(default)]
    pub worktree_dirty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDisposition {
    Reviewed,
    NotEligibleName,
    NotEligibleExtension,
    NotEligibleDirectory,
    Unreachable,
    OutOfDiffScope,
    BudgetSkipped,
    ChunkGuardrailed,
    ChunkFailed,
    Unchunked,
}

impl FileDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            FileDisposition::Reviewed => "reviewed",
            FileDisposition::NotEligibleName => "not_eligible_name",
            FileDisposition::NotEligibleExtension => "not_eligible_extension",
            FileDisposition::NotEligibleDirectory => "not_eligible_directory",
            FileDisposition::Unreachable => "unreachable",
            FileDisposition::OutOfDiffScope => "out_of_diff_scope",
            FileDisposition::BudgetSkipped => "budget_skipped",
            FileDisposition::ChunkGuardrailed => "chunk_guardrailed",
            FileDisposition::ChunkFailed => "chunk_failed",
            FileDisposition::Unchunked => "unchunked",
        }
    }

    pub const ALL: [FileDisposition; 10] = [
        FileDisposition::Reviewed,
        FileDisposition::NotEligibleName,
        FileDisposition::NotEligibleExtension,
        FileDisposition::NotEligibleDirectory,
        FileDisposition::Unreachable,
        FileDisposition::OutOfDiffScope,
        FileDisposition::BudgetSkipped,
        FileDisposition::ChunkGuardrailed,
        FileDisposition::ChunkFailed,
        FileDisposition::Unchunked,
    ];

    pub fn from_key(key: &str) -> Option<FileDisposition> {
        FileDisposition::ALL.into_iter().find(|d| d.as_str() == key)
    }

    pub fn reviewed(self) -> bool {
        self == FileDisposition::Reviewed
    }

    pub fn reason(self) -> &'static str {
        match self {
            FileDisposition::Reviewed => "reviewed",
            FileDisposition::NotEligibleName => "non-code filename",
            FileDisposition::NotEligibleExtension => "non-code extension",
            FileDisposition::NotEligibleDirectory => "under an excluded directory",
            FileDisposition::Unreachable => "not on a call path to a sink",
            FileDisposition::OutOfDiffScope => "outside the PR diff",
            FileDisposition::BudgetSkipped => "budget ran out before its chunk ran",
            FileDisposition::ChunkGuardrailed => "every chunk blocked by a provider guardrail",
            FileDisposition::ChunkFailed => "every chunk failed",
            FileDisposition::Unchunked => "never chunked (scanner defect)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_disposition_round_trips_through_its_serialized_key() {
        for d in FileDisposition::ALL {
            let key = d.as_str();
            assert_eq!(FileDisposition::from_key(key), Some(d), "{key}");
            assert_eq!(
                serde_json::to_value(d).unwrap(),
                serde_json::json!(key),
                "serde and as_str disagree for {d:?}"
            );
            let back: FileDisposition = serde_json::from_value(serde_json::json!(key)).unwrap();
            assert_eq!(back, d);
        }
    }

    #[test]
    fn all_holds_every_variant_exactly_once() {
        let keys: std::collections::BTreeSet<&str> =
            FileDisposition::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(keys.len(), FileDisposition::ALL.len());
    }

    #[test]
    fn an_unknown_key_is_not_guessed_at() {
        assert_eq!(FileDisposition::from_key("something_from_the_future"), None);
        assert_eq!(FileDisposition::from_key(""), None);
    }

    #[test]
    fn reviewed_is_the_only_disposition_that_counts_as_examined() {
        let reviewed: Vec<FileDisposition> = FileDisposition::ALL
            .into_iter()
            .filter(|d| d.reviewed())
            .collect();
        assert_eq!(reviewed, vec![FileDisposition::Reviewed]);
    }

    #[test]
    fn every_disposition_has_its_own_human_reason() {
        let mut seen = std::collections::BTreeSet::new();
        for d in FileDisposition::ALL {
            let reason = d.reason();
            assert!(!reason.is_empty(), "{d:?}");
            assert!(seen.insert(reason), "{d:?} reuses the reason {reason:?}");
        }
    }

    #[test]
    fn every_key_source_has_a_distinct_spelling() {
        let sources = [
            RepoKeySource::Explicit,
            RepoKeySource::Environment,
            RepoKeySource::Derived,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for s in sources {
            assert!(seen.insert(s.as_str()), "{s:?} reuses a spelling");
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::json!(s.as_str())
            );
        }
    }

    #[test]
    fn an_identity_from_an_older_report_deserializes_to_the_unresolved_case() {
        let id: RepoIdentity = serde_json::from_str("{}").unwrap();
        assert_eq!(id, RepoIdentity::default());
        assert!(id.key.is_none());
        assert!(!id.root_commit_verified);
    }
}
