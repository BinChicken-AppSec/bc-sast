#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMode {
    Annotate,
    Filter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub id: String,
    pub title: String,
    pub cwes: Vec<String>,
    pub vuln_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompliancePolicy {
    pub name: String,
    pub guidance: String,
    pub scope_mode: ScopeMode,
    pub requirements: Vec<Requirement>,
}
