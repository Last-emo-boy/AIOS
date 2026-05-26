use crate::agent_core::recovery::{RunRecoveryClass, RunRecoveryProjection, UnresolvedEffectTruth};
use crate::api::escape_json;
use crate::audit::{RuntimeAuditProjection, RuntimeAuditStepProjection, redact_summary};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackConsequencePreview {
    pub run_id: String,
    pub audit_events: usize,
    pub items: Vec<RollbackPreviewItem>,
}

impl RollbackConsequencePreview {
    pub fn collect(
        projection: &RunRecoveryProjection,
        audit: Option<&RuntimeAuditProjection>,
    ) -> Option<Self> {
        if projection.classification != RunRecoveryClass::NeedsRollback {
            return None;
        }

        let items = if projection.unresolved_effects.is_empty() {
            vec![RollbackPreviewItem::from_projection_without_effect(
                projection, audit,
            )]
        } else {
            projection
                .unresolved_effects
                .iter()
                .enumerate()
                .map(|(index, effect)| RollbackPreviewItem::from_effect(index, effect, audit))
                .collect()
        };

        Some(Self {
            run_id: projection.run_id.clone(),
            audit_events: audit.map(RuntimeAuditProjection::event_count).unwrap_or(0),
            items,
        })
    }

    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "rollback_preview source=run-store+audit-journal truth_source=audit-journal execution=preview-only mutates_state=false run={} items={} audit_ref=\"audit:{} events={}\"",
            self.run_id,
            self.items.len(),
            self.run_id,
            self.audit_events
        )];
        if self.items.is_empty() {
            lines.push(
                "rollback_preview[none] reason=\"no rollback-pending effect truth\"".to_string(),
            );
        } else {
            for (index, item) in self.items.iter().enumerate() {
                lines.push(item.render(index));
                lines.extend(item.render_evidence(index));
            }
        }
        lines
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPreviewItem {
    pub step_id: String,
    pub rollback_id: String,
    pub target_resource: String,
    pub affected_kind: String,
    pub base_hash: String,
    pub proposed_hash: String,
    pub final_hash: String,
    pub parameter_hash: String,
    pub effect_state: String,
    pub mode: String,
    pub automatic: bool,
    pub approval_required: bool,
    pub human_review_required: bool,
    pub failed_verification: bool,
    pub half_committed: bool,
    pub consequence: String,
    pub audit_ref: String,
    pub evidence: Vec<RollbackPreviewEvidence>,
}

impl RollbackPreviewItem {
    fn from_effect(
        index: usize,
        effect: &UnresolvedEffectTruth,
        audit: Option<&RuntimeAuditProjection>,
    ) -> Self {
        let step = audit.and_then(|projection| {
            projection
                .steps
                .iter()
                .find(|step| step.step_id == effect.step_id)
        });
        let evidence = rollback_evidence(step);
        let summary = combined_summary(effect, step);
        let rollback_id = first_summary_value(&summary, "rollback_id")
            .unwrap_or_else(|| format!("recovery-{}", effect.parameter_hash));
        let target_resource = first_summary_value(&summary, "target")
            .or_else(|| first_summary_value(&summary, "resource"))
            .or_else(|| first_summary_value(&summary, "service"))
            .unwrap_or_else(|| "-".to_string());
        let base_hash =
            first_summary_value(&summary, "base_hash").unwrap_or_else(|| "-".to_string());
        let proposed_hash =
            first_summary_value(&summary, "proposed_hash").unwrap_or_else(|| "-".to_string());
        let final_hash =
            first_summary_value(&summary, "final_hash").unwrap_or_else(|| "-".to_string());
        let effect_state = step
            .map(|step| step.effect_state.clone())
            .unwrap_or_else(|| {
                if effect.rollback_pending {
                    "rollback-pending".to_string()
                } else if effect.observed {
                    "observed-unsealed".to_string()
                } else {
                    "prepared-unsealed".to_string()
                }
            });
        let failed_verification =
            effect.rollback_pending || effect_state == "rollback-pending" || final_hash != "-";
        let half_committed = effect.prepared
            && !step.is_some_and(|step| step.commit_sealed)
            && (effect.observed || effect.rollback_pending || failed_verification);
        let mode = rollback_mode(&rollback_id, failed_verification, half_committed);
        let target_for_summary = if target_resource == "-" {
            "affected resource from audit".to_string()
        } else {
            target_resource.clone()
        };

        Self {
            step_id: effect.step_id.clone(),
            rollback_id: redact_rollback_text(&rollback_id),
            target_resource: redact_rollback_text(&target_resource),
            affected_kind: affected_kind(&target_resource, &summary),
            base_hash: redact_rollback_text(&base_hash),
            proposed_hash: redact_rollback_text(&proposed_hash),
            final_hash: redact_rollback_text(&final_hash),
            parameter_hash: redact_rollback_text(&effect.parameter_hash),
            effect_state,
            automatic: mode == "automatic",
            approval_required: mode == "requires-approval",
            human_review_required: mode == "requires-human-review",
            mode: mode.to_string(),
            failed_verification,
            half_committed,
            consequence: redact_rollback_text(&consequence_summary(
                &target_for_summary,
                &base_hash,
                failed_verification,
                half_committed,
            )),
            audit_ref: format!(
                "audit:{} step={} evidence={}",
                audit_run_id(audit),
                effect.step_id,
                evidence.len()
            ),
            evidence,
        }
        .with_index_fallback(index)
    }

    fn from_projection_without_effect(
        projection: &RunRecoveryProjection,
        audit: Option<&RuntimeAuditProjection>,
    ) -> Self {
        let step_id = projection
            .step_id
            .clone()
            .unwrap_or_else(|| "run".to_string());
        let step = audit
            .and_then(|projection| projection.steps.iter().find(|step| step.step_id == step_id));
        let evidence = rollback_evidence(step);
        let summary = step
            .map(step_summary)
            .unwrap_or_else(|| projection.reason.clone());
        let rollback_id =
            first_summary_value(&summary, "rollback_id").unwrap_or_else(|| "-".to_string());
        let target_resource = first_summary_value(&summary, "target")
            .or_else(|| first_summary_value(&summary, "resource"))
            .or_else(|| first_summary_value(&summary, "service"))
            .unwrap_or_else(|| "-".to_string());
        let base_hash =
            first_summary_value(&summary, "base_hash").unwrap_or_else(|| "-".to_string());

        Self {
            step_id: step_id.clone(),
            rollback_id: redact_rollback_text(&rollback_id),
            target_resource: redact_rollback_text(&target_resource),
            affected_kind: affected_kind(&target_resource, &summary),
            base_hash: redact_rollback_text(&base_hash),
            proposed_hash: redact_rollback_text(
                &first_summary_value(&summary, "proposed_hash").unwrap_or_else(|| "-".to_string()),
            ),
            final_hash: redact_rollback_text(
                &first_summary_value(&summary, "final_hash").unwrap_or_else(|| "-".to_string()),
            ),
            parameter_hash: "-".to_string(),
            effect_state: step
                .map(|step| step.effect_state.clone())
                .unwrap_or_else(|| "rollback-pending".to_string()),
            mode: "requires-human-review".to_string(),
            automatic: false,
            approval_required: false,
            human_review_required: true,
            failed_verification: true,
            half_committed: false,
            consequence: redact_rollback_text(&consequence_summary(
                &target_resource,
                &base_hash,
                true,
                false,
            )),
            audit_ref: format!(
                "audit:{} step={} evidence={}",
                audit_run_id(audit),
                step_id,
                evidence.len()
            ),
            evidence,
        }
    }

    fn with_index_fallback(mut self, index: usize) -> Self {
        if self.rollback_id.trim().is_empty() {
            self.rollback_id = format!("rollback-preview-{index}");
        }
        self
    }

    fn render(&self, index: usize) -> String {
        format!(
            "rollback_preview[{index}] step={} rollback_id={} target=\"{}\" affected_kind={} base_hash={} proposed_hash={} final_hash={} parameter_hash={} mode={} automatic={} approval_required={} human_review_required={} failed_verification={} half_committed={} effect_state={} audit_ref=\"{}\" consequence=\"{}\"",
            self.step_id,
            self.rollback_id,
            escape_json(&self.target_resource),
            self.affected_kind,
            self.base_hash,
            self.proposed_hash,
            self.final_hash,
            self.parameter_hash,
            self.mode,
            self.automatic,
            self.approval_required,
            self.human_review_required,
            self.failed_verification,
            self.half_committed,
            self.effect_state,
            escape_json(&self.audit_ref),
            escape_json(&self.consequence)
        )
    }

    fn render_evidence(&self, preview_index: usize) -> Vec<String> {
        if self.evidence.is_empty() {
            return vec![format!(
                "rollback_evidence[{preview_index}:none] source=audit-journal step={} reason=\"no rollback audit event projected\"",
                self.step_id
            )];
        }
        self.evidence
            .iter()
            .enumerate()
            .map(|(index, evidence)| {
                format!(
                    "rollback_evidence[{preview_index}:{index}] source=audit-journal step={} event={} parameter_hash={} summary=\"{}\"",
                    self.step_id,
                    evidence.event_type,
                    evidence.parameter_hash,
                    escape_json(&evidence.summary)
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPreviewEvidence {
    pub event_type: String,
    pub parameter_hash: String,
    pub summary: String,
}

fn rollback_evidence(step: Option<&RuntimeAuditStepProjection>) -> Vec<RollbackPreviewEvidence> {
    let Some(step) = step else {
        return Vec::new();
    };
    step.events
        .iter()
        .filter(|event| {
            matches!(
                event.event_type.as_str(),
                "EffectPrepared" | "EffectObserved" | "RollbackPending" | "RollbackObserved"
            )
        })
        .map(|event| RollbackPreviewEvidence {
            event_type: event.event_type.clone(),
            parameter_hash: redact_rollback_text(&event.parameter_hash),
            summary: redact_rollback_text(&event.summary),
        })
        .collect()
}

fn combined_summary(
    effect: &UnresolvedEffectTruth,
    step: Option<&RuntimeAuditStepProjection>,
) -> String {
    let mut parts = vec![effect.summary.clone()];
    if let Some(step) = step {
        parts.push(step_summary(step));
    }
    parts.join(" ")
}

fn step_summary(step: &RuntimeAuditStepProjection) -> String {
    step.events
        .iter()
        .map(|event| event.summary.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn first_summary_value(summary: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    summary.split_whitespace().find_map(|token| {
        token.strip_prefix(&prefix).and_then(|value| {
            let value = value
                .trim_matches(|ch: char| matches!(ch, ',' | ';' | '"' | '\'' | ')' | ']'))
                .to_string();
            if value.is_empty() { None } else { Some(value) }
        })
    })
}

fn rollback_mode(
    rollback_id: &str,
    failed_verification: bool,
    half_committed: bool,
) -> &'static str {
    if failed_verification || half_committed || rollback_id == "-" {
        "requires-human-review"
    } else {
        "requires-approval"
    }
}

fn affected_kind(target: &str, summary: &str) -> String {
    let lower = summary.to_ascii_lowercase();
    if lower.contains("service=") || lower.contains("svc.") {
        "service".to_string()
    } else if target.starts_with('/') || target.contains('\\') || target.contains('.') {
        "file".to_string()
    } else if target != "-" {
        "artifact".to_string()
    } else {
        "unknown".to_string()
    }
}

fn consequence_summary(
    target: &str,
    base_hash: &str,
    failed_verification: bool,
    half_committed: bool,
) -> String {
    let verification = if failed_verification {
        "failed verification"
    } else {
        "unsealed effect"
    };
    let commit_state = if half_committed {
        "half-committed effect"
    } else {
        "unsealed effect"
    };
    if base_hash == "-" {
        format!("{verification}; {commit_state}; inspect audit before rollback for {target}")
    } else {
        format!(
            "{verification}; {commit_state}; rollback would restore {target} to base_hash={base_hash}"
        )
    }
}

fn audit_run_id(audit: Option<&RuntimeAuditProjection>) -> String {
    audit
        .map(|projection| projection.run_id.clone())
        .unwrap_or_else(|| "missing".to_string())
}

fn redact_rollback_text(value: &str) -> String {
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
