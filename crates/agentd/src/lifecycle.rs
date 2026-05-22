use crate::api::{
    escape_json, CapabilityLease, CommitId, Effect, IntentCtx, PlanSpec, PlanStep, PolicyDecision,
    ReconciledState, RiskClass, RollbackResult, SemanticToolCall, VerificationResult,
};
use crate::modules::{ModuleKind, ModuleStatus};
use crate::tools::{RoutedToolCall, ToolRejection, ToolRouter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleConfig {
    pub run_mode: &'static str,
    pub planner_mode: &'static str,
    pub arbitrary_shell_enabled: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            run_mode: "local-only",
            planner_mode: "stub",
            arbitrary_shell_enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleState {
    Created,
    Running,
    Stopping,
    Stopped,
}

impl LifecycleState {
    fn as_str(&self) -> &'static str {
        match self {
            LifecycleState::Created => "created",
            LifecycleState::Running => "running",
            LifecycleState::Stopping => "stopping",
            LifecycleState::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub state: LifecycleState,
    pub run_mode: &'static str,
    pub planner_mode: &'static str,
    pub arbitrary_shell_enabled: bool,
    pub module_count: usize,
    pub last_error: Option<String>,
}

impl HealthReport {
    pub fn to_json(&self) -> String {
        let last_error = self
            .last_error
            .as_ref()
            .map(|error| format!("\"{}\"", escape_json(error)))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"state\":\"{}\",\"run_mode\":\"{}\",\"planner_mode\":\"{}\",\"arbitrary_shell_enabled\":{},\"module_count\":{},\"last_error\":{}}}",
            self.state.as_str(),
            self.run_mode,
            self.planner_mode,
            self.arbitrary_shell_enabled,
            self.module_count,
            last_error
        )
    }
}

#[derive(Debug)]
pub struct Agentd {
    config: LifecycleConfig,
    state: LifecycleState,
    modules: Vec<ModuleStatus>,
    last_error: Option<String>,
}

impl Agentd {
    pub fn new(config: LifecycleConfig) -> Self {
        let modules = ModuleKind::ALL
            .iter()
            .copied()
            .map(ModuleStatus::stub_ready)
            .collect();
        Self {
            config,
            state: LifecycleState::Created,
            modules,
            last_error: None,
        }
    }

    pub fn start(&mut self) {
        self.state = LifecycleState::Running;
    }

    pub fn stop(&mut self) {
        self.state = LifecycleState::Stopping;
        self.state = LifecycleState::Stopped;
    }

    pub fn record_error(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
    }

    pub fn module_statuses(&self) -> &[ModuleStatus] {
        &self.modules
    }

    pub fn health_report(&self) -> HealthReport {
        HealthReport {
            state: self.state.clone(),
            run_mode: self.config.run_mode,
            planner_mode: self.config.planner_mode,
            arbitrary_shell_enabled: self.config.arbitrary_shell_enabled,
            module_count: self.modules.len(),
            last_error: self.last_error.clone(),
        }
    }

    pub fn plan(&self, intent: impl Into<String>) -> PlanSpec {
        let ctx = IntentCtx {
            intent: intent.into(),
        };
        PlanSpec {
            run_mode: self.config.run_mode,
            intent: ctx.intent,
            steps: vec![PlanStep {
                id: "step-001".to_string(),
                tool: "svc.status".to_string(),
                risk: RiskClass::ReadOnly,
            }],
        }
    }

    pub fn classify(&self, step: &PlanStep) -> RiskClass {
        if step.tool == "shell.exec" {
            RiskClass::Never
        } else {
            step.risk
        }
    }

    pub fn evaluate(&self, step: &PlanStep) -> PolicyDecision {
        let risk = self.classify(step);
        PolicyDecision {
            allowed: risk != RiskClass::Never,
            risk,
            reason: if risk == RiskClass::Never {
                "normal mode denies arbitrary shell".to_string()
            } else {
                "stub policy allows deterministic local-only step".to_string()
            },
        }
    }

    pub fn acquire(&self, decision: &PolicyDecision) -> Result<CapabilityLease, String> {
        if !decision.allowed {
            return Err(decision.reason.clone());
        }
        Ok(CapabilityLease {
            lease_id: format!("lease-{}", decision.risk.as_str()),
            risk: decision.risk,
            expires_in_seconds: 60,
        })
    }

    pub fn invoke(&self, call: SemanticToolCall) -> Effect {
        Effect {
            prepared: true,
            observed: true,
            tool: call.name,
            summary: "stub effect only; no persistent side effects".to_string(),
        }
    }

    pub fn route_tool(&self, call: &SemanticToolCall) -> Result<RoutedToolCall, ToolRejection> {
        ToolRouter.route(call)
    }

    pub fn verify(&self, effect: &Effect) -> VerificationResult {
        VerificationResult {
            success: effect.prepared && effect.observed,
            reason: "stub verification over observed effect".to_string(),
        }
    }

    pub fn commit(&self, effect: &Effect) -> Result<CommitId, String> {
        let verification = self.verify(effect);
        if verification.success {
            Ok(CommitId("commit-stub-001".to_string()))
        } else {
            Err(verification.reason)
        }
    }

    pub fn rollback(&self, _commit_id: &CommitId) -> RollbackResult {
        RollbackResult {
            triggered: false,
            reason: "no persistent side effects in lifecycle skeleton".to_string(),
        }
    }

    pub fn recover(&self) -> ReconciledState {
        ReconciledState {
            unresolved_effects: 0,
        }
    }

    pub fn reap_children_once(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_local_only_stub_mode() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let health = agentd.health_report();
        assert_eq!(health.state, LifecycleState::Running);
        assert_eq!(health.run_mode, "local-only");
        assert_eq!(health.planner_mode, "stub");
        assert!(!health.arbitrary_shell_enabled);
        assert_eq!(health.module_count, 8);
    }

    #[test]
    fn exposes_all_required_module_boundaries() {
        let agentd = Agentd::new(LifecycleConfig::default());
        let modules = agentd
            .module_statuses()
            .iter()
            .map(|status| status.kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            modules,
            vec![
                "planner",
                "policy",
                "capability",
                "tool_router",
                "audit",
                "rollback",
                "model_broker",
                "tui",
            ]
        );
    }

    #[test]
    fn denies_arbitrary_shell_in_normal_mode() {
        let agentd = Agentd::new(LifecycleConfig::default());
        let step = PlanStep {
            id: "danger".to_string(),
            tool: "shell.exec".to_string(),
            risk: RiskClass::ReadOnly,
        };
        let decision = agentd.evaluate(&step);
        assert!(!decision.allowed);
        assert_eq!(decision.risk, RiskClass::Never);
        assert!(agentd.acquire(&decision).is_err());
    }

    #[test]
    fn stub_api_flow_returns_typed_results() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let plan = agentd.plan("check agentd");
        let step = plan.steps.first().expect("plan has a step");
        let decision = agentd.evaluate(step);
        let lease = agentd.acquire(&decision).expect("lease is issued");
        assert_eq!(lease.risk, RiskClass::ReadOnly);
        let effect = agentd.invoke(SemanticToolCall::new("svc.status", vec![("service", "agentd")]));
        assert!(agentd.verify(&effect).success);
        let commit = agentd.commit(&effect).expect("commit seals verified effect");
        assert!(!agentd.rollback(&commit).triggered);
        assert_eq!(agentd.recover().unresolved_effects, 0);
    }

    #[test]
    fn records_controlled_error_in_health_report() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        agentd.record_error("simulated controlled agentd error");
        let health = agentd.health_report();
        assert_eq!(
            health.last_error.as_deref(),
            Some("simulated controlled agentd error")
        );
    }
}
