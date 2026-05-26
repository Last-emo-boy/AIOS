use crate::agent_core::recovery::{RunRecoveryClass, RunRecoveryProjection, RunRecoveryReport};
use crate::agent_core::run_loop::RunProjection;
use crate::api::escape_json;
use crate::audit::{RuntimeAuditProjection, redact_summary};

use super::rollback_preview::RollbackConsequencePreview;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryWorkbench {
    pub selected_run_id: String,
    pub selected_state: String,
    pub selected_recovery: String,
    pub selected_reason: String,
    pub selected: Option<RunRecoveryProjection>,
    pub report: RunRecoveryReport,
    pub audit_reference: String,
    pub rollback_preview: Option<RollbackConsequencePreview>,
}

impl RecoveryWorkbench {
    pub fn collect(
        run: &RunProjection,
        report: RunRecoveryReport,
        audit: Option<&RuntimeAuditProjection>,
    ) -> Self {
        let selected = report
            .projections
            .iter()
            .find(|projection| projection.run_id == run.run_id)
            .cloned();
        let rollback_preview = selected
            .as_ref()
            .and_then(|projection| RollbackConsequencePreview::collect(projection, audit));
        Self {
            selected_run_id: run.run_id.clone(),
            selected_state: run.state.as_str().to_string(),
            selected_recovery: run.recovery_status.as_str().to_string(),
            selected_reason: redact_recovery_text(&run.recovery_reason),
            selected,
            report,
            audit_reference: audit_reference(audit),
            rollback_preview,
        }
    }

    pub fn empty() -> String {
        [
            "TUI Recovery",
            "panel=recovery-workbench source=run-store+audit-journal no-model-replay=true status=no-run run=- state=- recovery=- rollback_pending=false human_review=false degraded_optional_dependencies=visible baseline_operable=true action=\"inspect-only\" audit_ref=\"audit:no-run\"",
            "group safe-to-verify count=0",
            "group needs-rollback count=0",
            "group needs-human-review count=0",
            "group failed-closed count=0",
        ]
        .join("\n")
    }

    pub fn render(&self) -> String {
        let selected = self.selected.as_ref();
        let rollback_pending = selected
            .is_some_and(|projection| projection.classification == RunRecoveryClass::NeedsRollback)
            || self.selected_state == "RollbackPending";
        let human_review = selected.is_some_and(|projection| {
            projection.classification == RunRecoveryClass::NeedsHumanReview
        }) || matches!(
            self.selected_state.as_str(),
            "AwaitingApproval" | "Suspended" | "RollbackPending" | "FailedClosed"
        );
        let action = selected
            .map(next_action)
            .unwrap_or_else(|| "inspect-only".to_string());
        let selected_class = selected
            .map(|projection| projection.classification.as_str())
            .unwrap_or("completed");
        let selected_step = selected
            .and_then(|projection| projection.step_id.as_deref())
            .unwrap_or("-");
        let unresolved = selected
            .map(|projection| projection.unresolved_effects.len())
            .unwrap_or(0);
        let selected_prompt = selected
            .map(|projection| redact_recovery_text(&projection.prompt))
            .unwrap_or_else(|| "terminal or non-recoverable run; inspect audit only".to_string());
        let selected_reason = selected
            .map(|projection| redact_recovery_text(&projection.reason))
            .unwrap_or_else(|| self.selected_reason.clone());

        let mut lines = vec![
            "TUI Recovery".to_string(),
            format!(
                "panel=recovery-workbench source=run-store+audit-journal no-model-replay=true status={} run={} state={} recovery={} selected_class={} step={} rollback_pending={} human_review={} unresolved_effects={} degraded_optional_dependencies=visible baseline_operable=true action=\"{}\" audit_ref=\"{}\" reason=\"{}\" prompt=\"{}\"",
                selected_class,
                self.selected_run_id,
                self.selected_state,
                self.selected_recovery,
                selected_class,
                selected_step,
                rollback_pending,
                human_review,
                unresolved,
                escape_json(&action),
                escape_json(&self.audit_reference),
                escape_json(&selected_reason),
                escape_json(&selected_prompt)
            ),
        ];
        for class in [
            RunRecoveryClass::SafeToVerify,
            RunRecoveryClass::NeedsRollback,
            RunRecoveryClass::NeedsHumanReview,
            RunRecoveryClass::FailedClosed,
        ] {
            let items = self
                .report
                .projections
                .iter()
                .filter(|projection| projection.classification == class)
                .collect::<Vec<_>>();
            lines.push(format!("group {} count={}", class.as_str(), items.len()));
            if items.is_empty() {
                lines.push(format!(
                    "item[none] group={} reason=\"no recoverable runs\"",
                    class.as_str()
                ));
            } else {
                lines.extend(items.iter().enumerate().map(|(index, projection)| {
                    format!("item[{index}] {}", render_projection_item(projection))
                }));
            }
        }
        lines.extend(selected.into_iter().flat_map(render_unresolved_effects));
        if let Some(preview) = &self.rollback_preview {
            lines.extend(preview.render_lines());
        }
        lines.join("\n")
    }
}

fn render_projection_item(projection: &RunRecoveryProjection) -> String {
    format!(
        "run={} group={} previous_state={} restored_state={} recovery={} step={} unresolved_effects={} safe_next=\"{}\" audit_ref=\"{}\" reason=\"{}\"",
        projection.run_id,
        projection.classification.as_str(),
        projection.previous_state.as_str(),
        projection.restored_state.as_str(),
        projection.recovery_status.as_str(),
        projection.step_id.as_deref().unwrap_or("-"),
        projection.unresolved_effects.len(),
        escape_json(&next_action(projection)),
        escape_json(&format!("audit:{}", projection.run_id)),
        escape_json(&redact_recovery_text(&projection.reason))
    )
}

fn render_unresolved_effects(projection: &RunRecoveryProjection) -> Vec<String> {
    if projection.unresolved_effects.is_empty() {
        return vec!["unresolved[none] source=audit-journal".to_string()];
    }
    projection
        .unresolved_effects
        .iter()
        .enumerate()
        .map(|(index, effect)| {
            format!(
                "unresolved[{index}] source=audit-journal step={} parameter_hash={} prepared={} observed={} rollback_pending={} summary=\"{}\"",
                effect.step_id,
                redact_recovery_text(&effect.parameter_hash),
                effect.prepared,
                effect.observed,
                effect.rollback_pending,
                escape_json(&redact_recovery_text(&effect.summary))
            )
        })
        .collect()
}

fn next_action(projection: &RunRecoveryProjection) -> String {
    match projection.classification {
        RunRecoveryClass::SafeToVerify => format!("run.recover {}", projection.run_id),
        RunRecoveryClass::NeedsRollback => format!("audit.show {}", projection.run_id),
        RunRecoveryClass::NeedsHumanReview => format!("run.recover {}", projection.run_id),
        RunRecoveryClass::FailedClosed => format!("audit.show {}", projection.run_id),
        RunRecoveryClass::Abandoned => format!("audit.show {}", projection.run_id),
        RunRecoveryClass::Completed => "inspect-only".to_string(),
    }
}

fn audit_reference(audit: Option<&RuntimeAuditProjection>) -> String {
    audit
        .map(|projection| {
            format!(
                "audit:{} events={} warnings={}",
                projection.run_id,
                projection.event_count(),
                projection.warnings.len()
            )
        })
        .unwrap_or_else(|| "audit:missing".to_string())
}

fn redact_recovery_text(value: &str) -> String {
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
