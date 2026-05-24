pub use security_execution_crate::*;

#[cfg(test)]
#[test]
fn firecracker_facade_missing_dependencies_fail_before_effect_prepare() {
    use crate::api::{RiskClass, SemanticToolCall};
    use crate::runtime_contracts::ExecutionStep;
    use engine::SecurityExecutionEngine;

    #[derive(Clone)]
    struct FirecrackerStep {
        call: SemanticToolCall,
    }

    impl ExecutionStep for FirecrackerStep {
        fn step_id(&self) -> &str {
            "restart-agentd-firecracker"
        }

        fn call(&self) -> &SemanticToolCall {
            &self.call
        }

        fn planner_risk_hints(&self) -> Vec<RiskClass> {
            vec![RiskClass::ExecuteWithConfirmation]
        }

        fn rollback_required(&self) -> bool {
            false
        }
    }

    let root =
        std::env::temp_dir().join(format!("agentd-firecracker-facade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("temp dir");
    let journal = audit::AuditJournal::new(root.join("audit.jsonl"));
    let engine = engine::DefaultSecurityExecutionEngine::new(root.join("shadow"));
    let step = FirecrackerStep {
        call: SemanticToolCall::new("svc.restart", vec![("service", "agentd")]),
    };

    let initial = engine
        .prepare(
            &journal,
            engine::StepExecutionRequest::new("run-firecracker-facade", "operator", step.clone())
                .expect("request"),
        )
        .expect("initial approval pause");
    assert_eq!(
        initial.status,
        engine::PreparedExecutionStatus::AwaitingApproval
    );
    let policy_request = initial.outcome.request.as_ref().expect("policy request");
    let approval = policy::ApprovalToken {
        actor: policy_request.actor.clone(),
        tool: policy_request.tool.clone(),
        resource: policy_request.resource.clone(),
        parameter_hash: policy_request.parameter_hash.clone(),
        expires_at: policy_request.now + 60,
        policy_version: policy_request.policy_version.clone(),
    };
    let missing_probe = sandbox_profile::FirecrackerDependencyProbe::from_paths(
        root.join("missing-kvm"),
        root.join("missing-firecracker"),
        root.join("missing-jailer"),
        root.join("missing-vmlinux"),
        root.join("missing-rootfs.ext4"),
    );
    let profile = sandbox_profile::FirecrackerProfileRequest {
        firecracker_binary: root.join("missing-firecracker").display().to_string(),
        jailer_binary: root.join("missing-jailer").display().to_string(),
        kernel_image: root.join("missing-vmlinux").display().to_string(),
        rootfs_image: root.join("missing-rootfs.ext4").display().to_string(),
        network_mode: "restricted".to_string(),
        block_devices: vec!["rootfs:ro".to_string()],
        cpu_count: 2,
        memory_mib: 512,
        rate_limiter: "default-deny-egress".to_string(),
        snapshot_policy: "same-host-only".to_string(),
        dependency_probe: missing_probe,
    };

    let error = engine
        .prepare(
            &journal,
            engine::StepExecutionRequest::new("run-firecracker-facade", "operator", step)
                .expect("request")
                .with_approval(approval)
                .with_firecracker_profile(profile),
        )
        .expect_err("missing dependencies fail closed");

    assert_eq!(
        error.failure_class(),
        engine::ExecutionFailureClass::FailedClosed
    );
    assert!(error.reason().contains("firecracker dependencies missing"));
    assert!(!journal
        .event_lines()
        .expect("journal")
        .iter()
        .any(|line| line.contains("\"event_type\":\"EffectPrepared\"")));
}

#[cfg(test)]
#[test]
fn source_to_sink_facade_denies_untrusted_direct_action() {
    let source = source_to_sink::ContentSource::external_content("content-compat").expect("source");
    let sink = source_to_sink::SinkDescriptor::for_tool(
        "svc.restart",
        crate::api::RiskClass::ExecuteWithConfirmation,
        "agentd",
        vec![("service".to_string(), "agentd".to_string())],
    )
    .expect("sink");
    let request = source_to_sink::SourceToSinkRequest::new(
        "run-compat",
        "step-compat",
        "operator",
        source,
        sink,
    )
    .expect("request");

    let decision = source_to_sink::SourceToSinkPolicy
        .evaluate(&request)
        .expect("decision");

    assert_eq!(
        decision.kind,
        source_to_sink::SourceToSinkDecisionKind::Denied
    );
    assert!(decision.requires_sanitized_replanning);
}

#[cfg(test)]
mod compatibility {
    use super::effect_envelope::{EffectEnvelope, EffectEnvelopeState};
    use super::policy::{PolicyDecision, PolicyDecisionKind};
    use super::source_to_sink::{ContentSource, SinkDescriptor, SourceToSinkRequest};
    use crate::api::{RiskClass, SemanticToolCall};

    #[test]
    fn facade_exports_effect_envelope_paths() {
        let decision = PolicyDecision {
            kind: PolicyDecisionKind::Allow,
            risk: RiskClass::ReadOnly,
            reason: "compatibility smoke".to_string(),
        };
        let envelope = EffectEnvelope::draft(
            "run-compat",
            "step-compat",
            "svc.status",
            vec![("service".to_string(), "agentd".to_string())],
            decision,
        )
        .expect("draft");

        assert_eq!(envelope.state, EffectEnvelopeState::Draft);
    }

    #[test]
    fn facade_exports_source_to_sink_paths() {
        let source = ContentSource::external_content("content-compat").expect("source");
        let sink = SinkDescriptor::for_tool(
            "svc.restart",
            RiskClass::ExecuteWithConfirmation,
            "agentd",
            vec![("service".to_string(), "agentd".to_string())],
        )
        .expect("sink");
        let request =
            SourceToSinkRequest::new("run-compat", "step-compat", "operator", source, sink)
                .expect("request");

        assert_eq!(request.sink.tool, "svc.restart");
    }

    #[test]
    fn facade_exports_tool_router_paths() {
        let routed = super::tools::ToolRouter
            .route(&SemanticToolCall::new(
                "svc.status",
                vec![("service", "agentd")],
            ))
            .expect("route");

        assert_eq!(routed.risk, RiskClass::ReadOnly);
    }

    #[test]
    fn facade_exports_remote_audit_mirror_runtime_paths() {
        let root =
            std::env::temp_dir().join(format!("agentd-remote-audit-facade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp dir");
        let journal = super::audit::AuditJournal::new(root.join("local.jsonl"));
        journal
            .append(&super::audit::AuditEvent::new(
                super::audit::AuditEventType::PolicyEvaluated,
                "run-remote-audit",
                "step-remote-audit",
                "operator",
                "decision=allow token=abc secret://prod/db",
            ))
            .expect("local audit");

        let mirror = super::audit::FileRemoteAuditMirror::new(root.join("mirror.jsonl"));
        let decision = mirror
            .mirror_journal(
                &journal,
                &super::audit::RemoteAuditMirrorConfig::local_warn(),
            )
            .expect("mirror");

        assert_eq!(
            decision.status,
            super::audit::RemoteAuditMirrorStatus::Mirrored
        );
        assert!(decision.local_audit_authoritative);
        assert!(!decision.mirror_authoritative_for_recovery);
        let mirrored = super::audit::AuditJournal::new(mirror.path().to_path_buf())
            .event_lines()
            .expect("mirror lines");
        assert!(mirrored[0].contains("secret://prod/db"));
        assert!(mirrored[0].contains("[REDACTED]"));
        assert!(!mirrored[0].contains("token=abc"));
    }
}
