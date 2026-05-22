use crate::api::{escape_json, PlanSpec};
use crate::lifecycle::Agentd;
use crate::rollback::DiffPreview;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    Denied,
    TimedOut,
    Suspended,
}

impl ApprovalDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalDecision::Approved => "approved",
            ApprovalDecision::Denied => "denied",
            ApprovalDecision::TimedOut => "timed_out",
            ApprovalDecision::Suspended => "suspended",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub event: &'static str,
    pub detail: String,
}

impl AuditEvent {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"event\":\"{}\",\"detail\":\"{}\"}}",
            self.event,
            escape_json(&self.detail)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuiSession {
    pub intent: String,
    pub plan: PlanSpec,
    pub approval: ApprovalDecision,
    pub audit: Vec<AuditEvent>,
}

impl TuiSession {
    pub fn render(&self) -> String {
        let steps = self
            .plan
            .steps
            .iter()
            .map(|step| format!("  - {} :: {} [{}]", step.id, step.tool, step.risk.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        let audit = self
            .audit
            .iter()
            .map(|event| format!("  - {}: {}", event.event, event.detail))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            "AIOS agentd TUI\nIntent: {}\nPlan Preview:\n{}\nApproval: {}\nAudit:\n{}\n",
            self.intent,
            steps,
            self.approval.as_str(),
            audit
        )
    }

    pub fn audit_json(&self) -> String {
        let events = self
            .audit
            .iter()
            .map(AuditEvent::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!("[{events}]")
    }
}

pub fn build_demo_session(agentd: &Agentd, intent: impl Into<String>, approval: ApprovalDecision) -> TuiSession {
    let intent = intent.into();
    let plan = agentd.plan(&intent);
    let first_step = plan.steps.first().expect("stub planner always emits a step");
    let policy = agentd.evaluate(first_step);
    let mut audit = vec![
        AuditEvent {
            event: "IntentReceived",
            detail: intent.clone(),
        },
        AuditEvent {
            event: "PlanFrozen",
            detail: format!("{} step(s)", plan.steps.len()),
        },
        AuditEvent {
            event: "PolicyEvaluated",
            detail: format!("{} -> {}", first_step.tool, policy.risk.as_str()),
        },
        AuditEvent {
            event: "ApprovalDecision",
            detail: approval.as_str().to_string(),
        },
    ];

    if matches!(approval, ApprovalDecision::Approved) {
        let effect = agentd.invoke(crate::api::SemanticToolCall::new(
            &first_step.tool,
            vec![("source", "tui-demo")],
        ));
        audit.push(AuditEvent {
            event: "EffectObserved",
            detail: effect.summary,
        });
    }

    TuiSession {
        intent,
        plan,
        approval,
        audit,
    }
}

pub fn render_diff_preview(preview: &DiffPreview, approval: ApprovalDecision) -> String {
    format!(
        "{}\nApproval: {}\nAudit:\n  - DiffPreview: {}\n  - RollbackHandle: {}\n",
        preview.render(),
        approval.as_str(),
        preview.target_path.display(),
        preview.rollback_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{Agentd, LifecycleConfig};

    #[test]
    fn renders_plan_preview_and_audit() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let session = build_demo_session(&agentd, "recover local service", ApprovalDecision::Approved);
        let rendered = session.render();
        assert!(rendered.contains("AIOS agentd TUI"));
        assert!(rendered.contains("Intent: recover local service"));
        assert!(rendered.contains("Plan Preview"));
        assert!(rendered.contains("svc.status"));
        assert!(rendered.contains("Approval: approved"));
        assert!(rendered.contains("EffectObserved"));
    }

    #[test]
    fn supports_denial_timeout_and_suspended_states() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        for decision in [
            ApprovalDecision::Denied,
            ApprovalDecision::TimedOut,
            ApprovalDecision::Suspended,
        ] {
            let session = build_demo_session(&agentd, "recover local service", decision);
            assert!(session.render().contains(decision.as_str()));
            assert!(!session.render().contains("EffectObserved"));
        }
    }

    #[test]
    fn audit_json_records_policy_and_approval_projection() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let session = build_demo_session(&agentd, "recover local service", ApprovalDecision::Denied);
        let audit = session.audit_json();
        assert!(audit.contains("IntentReceived"));
        assert!(audit.contains("PlanFrozen"));
        assert!(audit.contains("PolicyEvaluated"));
        assert!(audit.contains("ApprovalDecision"));
        assert!(audit.contains("denied"));
    }

    #[test]
    fn renders_write_diff_preview_with_rollback_handle() {
        let preview = DiffPreview {
            target_path: "target.conf".into(),
            base_hash: "base".to_string(),
            proposed_hash: "next".to_string(),
            rollback_id: "rb-1".to_string(),
            unified_diff: "--- before\n+++ after\n-old\n+new".to_string(),
        };
        let rendered = render_diff_preview(&preview, ApprovalDecision::Suspended);
        assert!(rendered.contains("Diff Preview"));
        assert!(rendered.contains("-old"));
        assert!(rendered.contains("+new"));
        assert!(rendered.contains("RollbackHandle: rb-1"));
        assert!(rendered.contains("Approval: suspended"));
    }
}
