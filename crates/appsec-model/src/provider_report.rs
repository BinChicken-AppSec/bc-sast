use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProviderIngestionRecord {
    pub source: String,
    pub imported_count: usize,
    pub completed: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderAssessmentRecord {
    pub origin: crate::ProviderOrigin,
    pub file: String,
    pub line: i64,
    pub title: String,
    pub verification: Option<crate::VerificationEvidence>,
    pub drop_reason: Option<crate::DropReason>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProviderLedger {
    pub ingestion: Vec<ProviderIngestionRecord>,
    pub assessments: Vec<ProviderAssessmentRecord>,
    pub full_scan: bool,
    pub resumed: bool,
    pub analysis_complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ledger_roundtrip_retains_unassessed_origins_and_ingestion_failures() {
        let ledger = ProviderLedger {
            ingestion: vec![ProviderIngestionRecord {
                source: "semgrep-live".into(),
                imported_count: 0,
                completed: false,
                limitations: vec!["failed page".into()],
            }],
            assessments: vec![ProviderAssessmentRecord {
                origin: Default::default(),
                file: "app.rs".into(),
                line: 1,
                title: "candidate".into(),
                verification: None,
                drop_reason: None,
                limitations: vec!["not verified".into()],
            }],
            full_scan: true,
            resumed: false,
            analysis_complete: false,
        };
        let restored: ProviderLedger =
            serde_json::from_value(serde_json::to_value(&ledger).unwrap()).unwrap();
        assert_eq!(restored, ledger);
        assert!(!ProviderLedger::default().analysis_complete);
        assert!(!ProviderIngestionRecord::default().completed);
    }
}
