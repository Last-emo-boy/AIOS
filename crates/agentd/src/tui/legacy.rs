use crate::api::{PlanSpec, SemanticToolCall, escape_json};
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

pub fn build_demo_session(
    agentd: &Agentd,
    intent: impl Into<String>,
    approval: ApprovalDecision,
) -> TuiSession {
    let intent = intent.into();
    let plan = agentd.plan(&intent);
    let first_step = plan
        .steps
        .first()
        .expect("stub planner always emits a step");
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
        let effect = agentd.invoke(SemanticToolCall::new(
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
