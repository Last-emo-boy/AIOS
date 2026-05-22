use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
use crate::api::escape_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClassification {
    SafeToVerify,
    NeedsRollback,
    NeedsHumanReview,
    Abandoned,
}

impl RecoveryClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryClassification::SafeToVerify => "safe-to-verify",
            RecoveryClassification::NeedsRollback => "needs-rollback",
            RecoveryClassification::NeedsHumanReview => "needs-human-review",
            RecoveryClassification::Abandoned => "abandoned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryItem {
    pub step_id: String,
    pub classification: RecoveryClassification,
    pub reason: String,
}

impl RecoveryItem {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"step_id\":\"{}\",\"classification\":\"{}\",\"reason\":\"{}\"}}",
            escape_json(&self.step_id),
            self.classification.as_str(),
            escape_json(&self.reason)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub run_id: String,
    pub items: Vec<RecoveryItem>,
    pub requires_human_confirmation: bool,
}

impl RecoveryReport {
    pub fn to_json(&self) -> String {
        let items = self
            .items
            .iter()
            .map(RecoveryItem::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"run_id\":\"{}\",\"requires_human_confirmation\":{},\"items\":[{}]}}",
            escape_json(&self.run_id),
            self.requires_human_confirmation,
            items
        )
    }

    pub fn render_prompt(&self) -> String {
        if self.items.is_empty() {
            return format!("Recovery: run {} has no unresolved effects.", self.run_id);
        }
        let mut lines = vec![format!(
            "Recovery: run {} has {} unresolved effect(s).",
            self.run_id,
            self.items.len()
        )];
        for item in &self.items {
            lines.push(format!(
                "- {}: {} ({})",
                item.step_id,
                item.classification.as_str(),
                item.reason
            ));
        }
        if self.requires_human_confirmation {
            lines.push("Human confirmation required before continuation.".to_string());
        }
        lines.join("\n")
    }
}

#[derive(Debug, Default)]
pub struct RecoveryReconciler;

impl RecoveryReconciler {
    pub fn reconcile(&self, journal: &AuditJournal, run_id: &str) -> std::io::Result<RecoveryReport> {
        journal.append(&AuditEvent::new(
            AuditEventType::RecoveryStarted,
            run_id,
            "recovery",
            "agentd",
            "recovery scan started",
        ))?;

        let unresolved = journal.unresolved_effects()?;
        let items = unresolved
            .iter()
            .filter(|line| line.contains(&format!("\"run_id\":\"{run_id}\"")))
            .map(|line| {
                let step_id = extract_field(line, "step_id").unwrap_or_else(|| "unknown".to_string());
                let summary = extract_field(line, "summary").unwrap_or_default();
                RecoveryItem {
                    step_id,
                    classification: classify_summary(&summary),
                    reason: summary,
                }
            })
            .collect::<Vec<_>>();

        let requires_human_confirmation = items.iter().any(|item| {
            matches!(
                item.classification,
                RecoveryClassification::NeedsRollback | RecoveryClassification::NeedsHumanReview
            )
        });

        journal.append(&AuditEvent::new(
            AuditEventType::RecoveryCompleted,
            run_id,
            "recovery",
            "agentd",
            format!("recovery scan completed items={}", items.len()),
        ))?;

        Ok(RecoveryReport {
            run_id: run_id.to_string(),
            items,
            requires_human_confirmation,
        })
    }
}

pub fn classify_summary(summary: &str) -> RecoveryClassification {
    let lower = summary.to_ascii_lowercase();
    if lower.contains("read-only") || lower.contains("svc.status") || lower.contains("http.check") {
        RecoveryClassification::SafeToVerify
    } else if lower.contains("fs.write.diff") || lower.contains("write") || lower.contains("rollback") {
        RecoveryClassification::NeedsRollback
    } else if lower.contains("abandoned") {
        RecoveryClassification::Abandoned
    } else {
        RecoveryClassification::NeedsHumanReview
    }
}

fn extract_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_journal(name: &str) -> AuditJournal {
        let path = std::env::temp_dir().join(format!(
            "agentd-recovery-{name}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    #[test]
    fn classifies_unresolved_read_only_as_safe_to_verify() {
        let journal = test_journal("read-only");
        journal
            .append(&AuditEvent::new(
                AuditEventType::EffectPrepared,
                "run-read",
                "step-read",
                "operator",
                "prepared read-only svc.status",
            ))
            .expect("append prepared");
        let report = RecoveryReconciler
            .reconcile(&journal, "run-read")
            .expect("reconcile");
        assert_eq!(report.items.len(), 1);
        assert_eq!(
            report.items[0].classification,
            RecoveryClassification::SafeToVerify
        );
        assert!(!report.requires_human_confirmation);
    }

    #[test]
    fn classifies_unresolved_write_as_needs_rollback() {
        let journal = test_journal("write");
        journal
            .append(&AuditEvent::new(
                AuditEventType::EffectPrepared,
                "run-write",
                "step-write",
                "operator",
                "prepared fs.write.diff",
            ))
            .expect("append prepared");
        let report = RecoveryReconciler
            .reconcile(&journal, "run-write")
            .expect("reconcile");
        assert_eq!(
            report.items[0].classification,
            RecoveryClassification::NeedsRollback
        );
        assert!(report.requires_human_confirmation);
    }

    #[test]
    fn sealed_effect_does_not_appear_in_recovery_prompt() {
        let journal = test_journal("sealed");
        journal
            .append(&AuditEvent::new(
                AuditEventType::EffectPrepared,
                "run-sealed",
                "step-sealed",
                "operator",
                "prepared read-only svc.status",
            ))
            .expect("append prepared");
        journal
            .append(&AuditEvent::new(
                AuditEventType::CommitSealed,
                "run-sealed",
                "step-sealed",
                "operator",
                "sealed",
            ))
            .expect("append sealed");
        let report = RecoveryReconciler
            .reconcile(&journal, "run-sealed")
            .expect("reconcile");
        assert!(report.items.is_empty());
    }

    #[test]
    fn emits_recovery_started_and_completed_events() {
        let journal = test_journal("events");
        let _ = RecoveryReconciler
            .reconcile(&journal, "run-events")
            .expect("reconcile");
        let lines = journal.event_lines().expect("lines");
        assert!(lines.iter().any(|line| line.contains("RecoveryStarted")));
        assert!(lines.iter().any(|line| line.contains("RecoveryCompleted")));
    }
}
