use crate::agent_core::run_loop::RunProjection;
use crate::api::escape_json;
use crate::audit::{RuntimeAuditProjection, RuntimeAuditStepProjection, redact_summary};

use super::render::{ApprovalBinding, approval_queue_status, binding_for_step};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCenterPanel {
    pub run_id: String,
    pub queue_status: String,
    pub blocked_reason: String,
    pub item: ApprovalCenterItem,
}

impl ApprovalCenterPanel {
    pub fn collect(
        run: &RunProjection,
        audit: Option<&RuntimeAuditProjection>,
    ) -> Result<Self, String> {
        let step_id = run.current_step_id.as_deref().unwrap_or("-");
        let binding = audit.and_then(|projection| binding_for_step(projection, step_id));
        let actionable = run.approval_status.as_str() == "Pending";
        if actionable && binding.is_none() {
            return Err(format!(
                "approval center missing exact binding context for actionable approval run={} step={}",
                run.run_id, step_id
            ));
        }
        let audit_step = audit
            .and_then(|projection| projection.steps.iter().find(|step| step.step_id == step_id));
        let item = ApprovalCenterItem::from_run(run, step_id, binding.as_ref(), audit_step);
        Ok(Self {
            run_id: run.run_id.clone(),
            queue_status: approval_queue_status(run).to_string(),
            blocked_reason: redact_approval_text(&run.approval_reason),
            item,
        })
    }

    pub fn render(&self) -> String {
        let actionable_count = usize::from(self.item.actionable);
        let non_actionable_count = usize::from(!self.item.actionable);
        let mut lines = vec![
            "TUI Approvals".to_string(),
            format!(
                "panel=approval-center source=run-store+audit-journal exact_binding_required=true run={} queue_status={} actionable_count={} non_actionable_count={} expired_count={} denied_count={} stale_count={} command_weight=equal authority=\"AgentCore approval state + SecurityExecutionEngine audit binding\" blocked_reason=\"{}\"",
                self.run_id,
                self.queue_status,
                actionable_count,
                non_actionable_count,
                usize::from(self.item.expired),
                usize::from(self.item.denied),
                usize::from(self.item.stale),
                escape_json(&self.blocked_reason)
            ),
            format!("section=actionable count={actionable_count}"),
        ];
        if self.item.actionable {
            lines.push(format!("item[0] {}", self.item.render_fields()));
        } else {
            lines.push(
                "item[none] section=actionable reason=\"no exact pending approval\"".to_string(),
            );
        }
        lines.push(format!(
            "section=non-actionable count={non_actionable_count}"
        ));
        if self.item.actionable {
            lines.push("item[none] section=non-actionable reason=\"no expired, denied or stale approvals for selected run\"".to_string());
        } else {
            lines.push(format!("item[0] {}", self.item.render_fields()));
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCenterItem {
    pub section: &'static str,
    pub run_id: String,
    pub step_id: String,
    pub approval_status: String,
    pub actor: String,
    pub tool: String,
    pub resource: String,
    pub parameter_hash: String,
    pub parameter_summary: String,
    pub requested_binding_hash: String,
    pub bound_token_hash: String,
    pub binding_diff: String,
    pub policy_version: String,
    pub expires_at: String,
    pub expires_in: String,
    pub stale: bool,
    pub expired: bool,
    pub denied: bool,
    pub actionable: bool,
    pub exact_binding_available: bool,
    pub preview_state: String,
    pub disabled_reason: String,
    pub reason: String,
    pub policy_reason: String,
    pub rollback_consequence: String,
    pub approve_command: String,
    pub deny_command: String,
}

impl ApprovalCenterItem {
    fn from_run(
        run: &RunProjection,
        step_id: &str,
        binding: Option<&ApprovalBinding>,
        audit_step: Option<&RuntimeAuditStepProjection>,
    ) -> Self {
        let status = run.approval_status.as_str();
        let expired = status == "Expired";
        let denied = status == "Denied";
        let (actor, tool, resource, parameter_hash, policy_version, expires_at) = binding
            .map(binding_fields)
            .unwrap_or_else(empty_binding_fields);
        let parameter_summary = binding
            .map(|binding| {
                format!(
                    "tool={} resource={} hash={}",
                    redact_approval_text(&binding.tool),
                    redact_approval_text(&binding.resource),
                    redact_approval_text(&binding.parameter_hash)
                )
            })
            .unwrap_or_else(|| "unavailable".to_string());
        let requested_binding_hash = audit_step
            .and_then(policy_parameter_hash)
            .map(redact_approval_text)
            .unwrap_or_else(|| "-".to_string());
        let bound_token_hash = parameter_hash.clone();
        let binding_diff = binding_diff(&requested_binding_hash, &bound_token_hash);
        let actionable = status == "Pending" && binding.is_some() && binding_diff == "match";
        let stale = matches!(status, "Granted")
            || (!actionable && binding.is_some() && !expired)
            || binding_diff == "mismatch-denied-preview";
        let section = if actionable {
            "actionable"
        } else {
            "non-actionable"
        };
        let preview_state = if binding_diff == "mismatch-denied-preview" {
            "denied-preview"
        } else if actionable {
            "ready"
        } else if expired {
            "expired"
        } else if denied {
            "denied"
        } else if stale {
            "stale"
        } else {
            "blocked"
        }
        .to_string();
        let expires_in = binding
            .map(|binding| binding.expires_at.saturating_sub(0).to_string())
            .unwrap_or_else(|| "-".to_string());
        let disabled_reason = disabled_reason(
            status,
            actionable,
            stale,
            expired,
            denied,
            binding.is_some(),
            &binding_diff,
        );
        let rollback_consequence = audit_step
            .map(rollback_consequence)
            .unwrap_or_else(|| "side_effects_closed_until_approval".to_string());
        let policy_reason = audit_step
            .and_then(|step| step.policy_summary.as_deref())
            .map(redact_approval_text)
            .unwrap_or_else(|| "policy_summary_unavailable".to_string());
        let reason = redact_approval_text(&run.approval_reason);
        let approve_command = if actionable {
            format!("run.approve latest {step_id} actor={actor}")
        } else {
            "-".to_string()
        };
        let deny_command = if actionable {
            format!("run.deny latest {step_id} actor={actor} reason=<text>")
        } else {
            "-".to_string()
        };

        Self {
            section,
            run_id: run.run_id.clone(),
            step_id: step_id.to_string(),
            approval_status: status.to_string(),
            actor,
            tool,
            resource,
            parameter_hash,
            parameter_summary,
            requested_binding_hash,
            bound_token_hash,
            binding_diff,
            policy_version,
            expires_at,
            expires_in,
            stale,
            expired,
            denied,
            actionable,
            exact_binding_available: binding.is_some(),
            preview_state,
            disabled_reason,
            reason,
            policy_reason,
            rollback_consequence,
            approve_command,
            deny_command,
        }
    }

    fn render_fields(&self) -> String {
        format!(
            "section={} run={} step={} approval={} actor={} tool={} resource={} parameter_hash={} parameter_summary=\"{}\" requested_binding_hash={} bound_token_hash={} binding_diff={} policy_version={} expires_at={} expires_in={} stale={} expired={} denied={} actionable={} exact_binding_available={} preview_state={} disabled_reason=\"{}\" reason=\"{}\" policy_reason=\"{}\" rollback_consequence=\"{}\" approve=\"{}\" deny=\"{}\"",
            self.section,
            self.run_id,
            self.step_id,
            self.approval_status,
            self.actor,
            self.tool,
            self.resource,
            self.parameter_hash,
            escape_json(&self.parameter_summary),
            self.requested_binding_hash,
            self.bound_token_hash,
            self.binding_diff,
            self.policy_version,
            self.expires_at,
            self.expires_in,
            self.stale,
            self.expired,
            self.denied,
            self.actionable,
            self.exact_binding_available,
            self.preview_state,
            escape_json(&self.disabled_reason),
            escape_json(&self.reason),
            escape_json(&self.policy_reason),
            escape_json(&self.rollback_consequence),
            escape_json(&self.approve_command),
            escape_json(&self.deny_command)
        )
    }
}

fn binding_fields(binding: &ApprovalBinding) -> (String, String, String, String, String, String) {
    (
        redact_approval_text(&binding.actor),
        redact_approval_text(&binding.tool),
        redact_approval_text(&binding.resource),
        redact_approval_text(&binding.parameter_hash),
        redact_approval_text(&binding.policy_version),
        binding.expires_at.to_string(),
    )
}

fn empty_binding_fields() -> (String, String, String, String, String, String) {
    (
        "-".to_string(),
        "-".to_string(),
        "-".to_string(),
        "-".to_string(),
        "-".to_string(),
        "-".to_string(),
    )
}

fn policy_parameter_hash(step: &RuntimeAuditStepProjection) -> Option<&str> {
    step.events
        .iter()
        .rev()
        .find(|event| event.event_type == "PolicyEvaluated")
        .map(|event| event.parameter_hash.as_str())
        .filter(|hash| !hash.is_empty() && *hash != "unset")
}

fn binding_diff(requested_hash: &str, bound_hash: &str) -> String {
    if requested_hash == "-" || bound_hash == "-" {
        "unavailable".to_string()
    } else if requested_hash == bound_hash {
        "match".to_string()
    } else {
        "mismatch-denied-preview".to_string()
    }
}

fn disabled_reason(
    status: &str,
    actionable: bool,
    stale: bool,
    expired: bool,
    denied: bool,
    binding_available: bool,
    binding_diff: &str,
) -> String {
    if actionable {
        return "-".to_string();
    }
    if binding_diff == "mismatch-denied-preview" {
        return "approval binding mismatch denied before effect preparation".to_string();
    }
    if expired {
        return "expired approval cannot be submitted".to_string();
    }
    if stale {
        return "stale approval token cannot be reused".to_string();
    }
    if denied {
        return "denied approval cannot be submitted".to_string();
    }
    if !binding_available {
        return "missing exact binding context".to_string();
    }
    format!("approval status {status} is not actionable")
}

fn rollback_consequence(step: &RuntimeAuditStepProjection) -> String {
    if step.effect_prepared || step.effect_state == "rollback-pending" {
        format!(
            "effect_state={} rollback_attention_required",
            step.effect_state
        )
    } else {
        "side_effects_closed_until_approval".to_string()
    }
}

fn redact_approval_text(value: &str) -> String {
    redact_inline_secret_assignments(&redact_summary(value))
}

fn redact_inline_secret_assignments(value: &str) -> String {
    let mut output = value.to_string();
    loop {
        let lower = output.to_ascii_lowercase();
        let found = [
            "password=",
            "token=",
            "apikey=",
            "api_key=",
            "access_token=",
            "secret=",
        ]
        .iter()
        .filter_map(|key| lower.find(key).map(|index| (index, *key)))
        .min_by_key(|(index, _)| *index);
        let Some((start, key)) = found else {
            return output;
        };
        let bytes = output.as_bytes();
        let mut end = start + key.len();
        while end < bytes.len()
            && !bytes[end].is_ascii_whitespace()
            && !matches!(bytes[end], b'"' | b'\'' | b',' | b']' | b')')
        {
            end += 1;
        }
        output.replace_range(start..end, "[REDACTED]");
    }
}
