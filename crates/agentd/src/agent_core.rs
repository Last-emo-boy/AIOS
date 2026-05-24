pub use agent_core_crate::*;

#[cfg(test)]
mod compatibility {
    use super::model::{IntentCtx, IntentSource, ModelEvidence, PlanSpec, TrustBoundary};
    use super::model_broker::{ModelBroker, ModelCallBounds, StubModelProvider, SummarizeRequest};
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

    #[test]
    fn facade_exports_host_promotion_paths() {
        let request = super::host_promotion::HostPromotionRequest::new(
            "operator",
            "run-host-promotion-facade",
            "promote-package-to-host",
            "pkg.host.install",
            "nginx-agent-plugin@1.2.3",
            "https://packages.example/nginx-agent-plugin_1.2.3.deb",
            "sha256:0123456789abcdef",
            "package-manager",
            "adapter-v1",
        )
        .expect("request")
        .with_rollback_handle("rollback-package-nginx-agent-plugin-1.2.3");
        let verification = super::host_promotion::HostPromotionVerificationEvidence::from_report(
            "host-package-active",
            false,
            "host package smoke failed",
        )
        .expect("verification");
        let approval = request.exact_approval(&verification, 0);
        let path = std::env::temp_dir().join(format!(
            "agentd-host-promotion-facade-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let journal = crate::security_execution::audit::AuditJournal::new(path);

        let decision = super::host_promotion::HostPromotionWorkflow
            .evaluate_and_audit(&journal, &request, verification, Some(&approval), 0)
            .expect("decision");

        assert_eq!(
            decision.kind,
            super::host_promotion::HostPromotionDecisionKind::RollbackPending
        );
        let projection = decision.audit_projection.expect("projection");
        assert!(projection.steps.iter().any(|step| {
            step.step_id == "promote-package-to-host" && step.effect_state == "rollback-pending"
        }));
    }

    #[test]
    fn facade_exports_rootfs_update_paths() {
        let artifacts = super::rootfs_update::UpdateArtifactSet::new(
            "sha256:release-manifest",
            "sha256:rootfs",
            "sha256:provenance",
            "sha256:sbom",
            "sha256:signature",
            "sha256:update-metadata",
        )
        .expect("artifacts")
        .with_validation_hash("sha256:validation")
        .expect("validation");
        let request = super::rootfs_update::RootfsUpdateRequest::new(
            "operator",
            "run-update-facade",
            super::rootfs_update::RootfsSlot::A,
            super::rootfs_update::RootfsSlot::B,
            "file://updates/rootfs.img",
            artifacts,
        )
        .expect("request")
        .with_preflight_verified()
        .with_state_backup_ready();
        let path = std::env::temp_dir().join(format!(
            "agentd-rootfs-update-facade-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let journal = crate::security_execution::audit::AuditJournal::new(path);

        let decision = super::rootfs_update::RootfsUpdateRuntime
            .stage_update(&journal, &request)
            .expect("stage");

        assert_eq!(
            decision.state,
            super::rootfs_update::UpdateState::ActivationScheduled
        );
        assert!(!decision.active_slot_modified);
        assert!(decision.to_json().contains("\"pending_slot\":\"B\""));
    }
}

#[cfg(test)]
mod adversarial {
    use super::model::PlanStep;
    use super::model::{ApprovalRequirement, RiskHint, RollbackRequirement, VerificationRule};
    use crate::security_execution::audit::AuditJournal;
    use crate::security_execution::policy::PolicyEvaluator;
    use crate::security_execution::policy_adapter::{PlanStepPolicyAdapter, StepPolicyOutcomeKind};
    use crate::security_execution::tools::ToolRouter;
    use runtime_contracts::{RiskClass, SemanticToolCall};

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
                RiskHint::new(
                    RiskClass::ReadOnly,
                    "planner tried to downgrade restart risk",
                )
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
        assert_eq!(
            outcome.diagnostic.authoritative_risk,
            RiskClass::ExecuteWithConfirmation
        );
        assert_eq!(
            outcome.diagnostic.planner_risk_hints,
            vec![RiskClass::ReadOnly]
        );
        assert!(outcome.lease.is_none());
        assert!(
            journal
                .event_lines()
                .expect("audit")
                .iter()
                .all(|line| !line.contains("\"event_type\":\"EffectPrepared\""))
        );
    }
}
