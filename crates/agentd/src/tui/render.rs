use crate::agent_core::run_loop::RunProjection;
use crate::audit::{RuntimeAuditProjection, RuntimeAuditStepProjection, redact_summary};
use crate::operator_projection::OperatorProjection;

pub fn render_run_projection(projection: RunProjection) -> String {
    format!(
        "TUI Run\n{}\nplan={} frozen_plan_hash={} approval_id={} approval_reason=\"{}\" recovery={} recovery_reason=\"{}\" memory_refs={}\n",
        projection.to_cli_line(),
        projection.plan_id,
        projection.frozen_plan_hash,
        projection.approval_id.as_deref().unwrap_or("-"),
        redact_summary(&projection.approval_reason),
        projection.recovery_status.as_str(),
        redact_summary(&projection.recovery_reason),
        projection.memory_count
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalBinding {
    pub(crate) actor: String,
    pub(crate) tool: String,
    pub(crate) resource: String,
    pub(crate) parameter_hash: String,
    pub(crate) policy_version: String,
    pub(crate) expires_at: u64,
}

pub(crate) fn binding_for_step(
    projection: &RuntimeAuditProjection,
    step_id: &str,
) -> Option<ApprovalBinding> {
    let step = projection
        .steps
        .iter()
        .find(|step| step.step_id == step_id)?;
    binding_from_step(step)
}

fn binding_from_step(step: &RuntimeAuditStepProjection) -> Option<ApprovalBinding> {
    let event = step.events.iter().rev().find(|event| {
        event.event_type == "PolicyEvaluated" && event.summary.contains("pause-for-approval")
    })?;
    Some(ApprovalBinding {
        actor: event.actor.clone(),
        tool: summary_value(&event.summary, "tool").unwrap_or_else(|| "-".to_string()),
        resource: summary_value(&event.summary, "resource").unwrap_or_else(|| "-".to_string()),
        parameter_hash: non_empty(&event.parameter_hash)?,
        policy_version: non_empty(&event.policy_version)?,
        expires_at: 60,
    })
}

pub(crate) fn approval_queue_status(projection: &RunProjection) -> &'static str {
    match projection.approval_status.as_str() {
        "Pending" => "pending",
        "Denied" => "denied",
        "Expired" => "expired",
        "Granted" => "granted",
        _ => "none",
    }
}

fn summary_value(summary: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    summary
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
        .map(ToString::to_string)
        .filter(|value| !value.is_empty())
}

fn non_empty(value: &str) -> Option<String> {
    if value.trim().is_empty() || value == "unset" {
        None
    } else {
        Some(value.to_string())
    }
}

pub fn render_help() -> String {
    [
        "TUI Help",
        "dashboard.show",
        "palette.preview <typed-command>",
        "intent.submit <operator intent>",
        "run.show <run-id|latest>",
        "run.advance <run-id>",
        "run.approve <run-id> <step-id> actor=<actor>",
        "run.deny <run-id> <step-id> actor=<actor> reason=<text>",
        "run.suspend <run-id> reason=<text>",
        "run.recover <run-id>",
        "audit.show <run-id|latest>",
        "events.show [limit]",
        "approvals.show <run-id|latest>",
        "recovery.show <run-id|latest>",
        "support.bundle status|export",
        "capabilities.show",
        "capability.list",
        "workflows.show [workflow-id]",
        "launch.preview <workflow-id> [key=value ...]",
        "aom.artifact.show <coordinate>",
        "release.provenance.show",
        "promotion.blockers.show",
        "update.rollback.show",
        "gate.status.show",
        "signing.status.show",
        "rollout.rings.show",
        "aom.search [registry-path]",
        "aom.show <coordinate> [registry-path]",
        "aom.verify <coordinate> [registry-path]",
        "aom.stage <coordinate> [registry-path] [staging-root]",
        "aom.explain <coordinate> [registry-path]",
        "aom.activate.preview <coordinate> [registry-path] [staging-root]",
        "refresh",
        "exit",
        "No shell syntax is accepted.",
        "",
    ]
    .join("\n")
}

pub fn render_runtime_audit_projection(projection: &RuntimeAuditProjection) -> String {
    format!(
        "Runtime Audit Projection\n{}\n",
        projection.to_cli_lines().join("\n")
    )
}

pub fn render_operator_projection(projection: &OperatorProjection) -> String {
    format!("Operator Projection\n{}\n", projection.to_cli_text())
}
