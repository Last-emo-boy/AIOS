pub use agent_core_crate::*;

#[cfg(test)]
mod compatibility {
    use super::model::{IntentCtx, IntentSource, ModelEvidence, PlanSpec, TrustBoundary};
    use super::model_broker::{
        ModelBroker, ModelCallBounds, StubModelProvider, SummarizeRequest,
    };
    use super::planner::{DeterministicPlanner, Planner};
    use runtime_contracts::SemanticToolCall;

    #[test]
    fn facade_exports_model_paths() {
        let intent = IntentCtx::new(
            "operator",
            TrustBoundary::Operator,
            IntentSource::TestFixture,
            "vm:compat",
            "compat",
        )
        .expect("intent");
        let plan = PlanSpec::new(
            "plan-compat",
            "stub-planner-v1",
            intent,
            Vec::new(),
            vec!["compat smoke passed".to_string()],
            ModelEvidence::stub(),
        )
        .expect("plan");

        assert!(plan.to_json().contains("plan-compat"));
    }

    #[test]
    fn facade_exports_planner_paths() {
        let planner = DeterministicPlanner::stub();
        let intent = IntentCtx::new(
            "operator",
            TrustBoundary::Operator,
            IntentSource::TestFixture,
            "vm:compat",
            "recover nginx",
        )
        .expect("intent");

        let plan = planner.draft_plan("compat", intent).expect("draft");
        assert!(!plan.steps().is_empty());
    }

    #[test]
    fn facade_exports_model_broker_paths() {
        let provider = StubModelProvider::default();
        let bounds = ModelCallBounds::new(1000, 1024).expect("bounds");
        let request = SummarizeRequest::new("compat", "system healthy", bounds).expect("request");
        let response = provider.summarize(&request).expect("summary");

        assert!(response.summary.contains("system healthy"));
    }

    #[test]
    fn facade_keeps_runtime_contract_types_usable() {
        let call = SemanticToolCall::new("svc.status", vec![("service", "agentd")]);
        assert_eq!(call.name, "svc.status");
    }
}

#[cfg(test)]
mod adversarial {
    use super::model::{
        ApprovalRequirement, RiskHint, RollbackRequirement, VerificationRule,
    };
    use super::model::PlanStep;
    use runtime_contracts::{RiskClass, SemanticToolCall};
    use crate::security_execution::audit::AuditJournal;
    use crate::security_execution::policy::PolicyEvaluator;
    use crate::security_execution::policy_adapter::{
        PlanStepPolicyAdapter, StepPolicyOutcomeKind,
    };
    use crate::security_execution::tools::ToolRouter;

    #[test]
    fn planner_risk_downgrade_still_pauses_before_effects() {
        let path = std::env::temp_dir().join(format!(
            "agentd-agent-core-facade-adversarial-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let journal = AuditJournal::new(path);
        let step = PlanStep::new(
            "restart-service",
            SemanticToolCall::new("svc.restart", vec![("service", "nginx")]),
            Vec::new(),
            vec!["diagnostics reviewed".to_string()],
            vec!["restart attempt observed".to_string()],
            VerificationRule::new(
                "service-active-after-restart",
                "service reports active after restart",
                "svc.status",
            )
            .expect("verification"),
            ApprovalRequirement::not_required("malicious planner claimed restart was read-only")
                .expect("approval"),
            1,
            vec![
                RiskHint::new(RiskClass::ReadOnly, "planner tried to downgrade restart risk")
                    .expect("risk"),
            ],
            RollbackRequirement::new(
                true,
                Some("rollback-service-restart"),
                "restart requires recovery reconciliation",
            )
            .expect("rollback"),
        )
        .expect("step");

        let outcome = PlanStepPolicyAdapter::new(ToolRouter, PolicyEvaluator)
            .evaluate_step(&journal, "run-adversarial", "operator", &step, None)
            .expect("policy outcome");

        assert_eq!(outcome.kind, StepPolicyOutcomeKind::AwaitingApproval);
        assert_eq!(outcome.diagnostic.authoritative_risk, RiskClass::ExecuteWithConfirmation);
        assert_eq!(outcome.diagnostic.planner_risk_hints, vec![RiskClass::ReadOnly]);
        assert!(outcome.lease.is_none());
        assert!(journal
            .event_lines()
            .expect("audit")
            .iter()
            .all(|line| !line.contains("\"event_type\":\"EffectPrepared\"")));
    }
}
