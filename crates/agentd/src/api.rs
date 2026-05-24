pub use runtime_contracts::{RiskClass, SemanticToolCall};
pub use security_execution_crate::{CommitId, VerificationResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentCtx {
    pub intent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSpec {
    pub run_mode: &'static str,
    pub intent: String,
    pub steps: Vec<PlanStep>,
}

impl PlanSpec {
    pub fn to_json(&self) -> String {
        let steps = self
            .steps
            .iter()
            .map(PlanStep::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"run_mode\":\"{}\",\"intent\":\"{}\",\"steps\":[{}]}}",
            self.run_mode,
            escape_json(&self.intent),
            steps
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub id: String,
    pub tool: String,
    pub risk: RiskClass,
}

impl PlanStep {
    fn to_json(&self) -> String {
        format!(
            "{{\"id\":\"{}\",\"tool\":\"{}\",\"risk\":\"{}\"}}",
            escape_json(&self.id),
            escape_json(&self.tool),
            self.risk.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub risk: RiskClass,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityLease {
    pub lease_id: String,
    pub risk: RiskClass,
    pub expires_in_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub prepared: bool,
    pub observed: bool,
    pub tool: String,
    pub summary: String,
}

impl Effect {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"prepared\":{},\"observed\":{},\"tool\":\"{}\",\"summary\":\"{}\"}}",
            self.prepared,
            self.observed,
            escape_json(&self.tool),
            escape_json(&self.summary)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackResult {
    pub triggered: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledState {
    pub unresolved_effects: usize,
}

pub fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}
