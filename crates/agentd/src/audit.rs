use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::api::escape_json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    IntentReceived,
    PlanFrozen,
    PolicyEvaluated,
    ApprovalBound,
    EffectPrepared,
    EffectObserved,
    CommitSealed,
    RollbackPending,
    RollbackObserved,
    RecoveryStarted,
    RecoveryCompleted,
    SandboxDenied,
}

impl AuditEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditEventType::IntentReceived => "IntentReceived",
            AuditEventType::PlanFrozen => "PlanFrozen",
            AuditEventType::PolicyEvaluated => "PolicyEvaluated",
            AuditEventType::ApprovalBound => "ApprovalBound",
            AuditEventType::EffectPrepared => "EffectPrepared",
            AuditEventType::EffectObserved => "EffectObserved",
            AuditEventType::CommitSealed => "CommitSealed",
            AuditEventType::RollbackPending => "RollbackPending",
            AuditEventType::RollbackObserved => "RollbackObserved",
            AuditEventType::RecoveryStarted => "RecoveryStarted",
            AuditEventType::RecoveryCompleted => "RecoveryCompleted",
            AuditEventType::SandboxDenied => "SandboxDenied",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "IntentReceived" => Self::IntentReceived,
            "PlanFrozen" => Self::PlanFrozen,
            "PolicyEvaluated" => Self::PolicyEvaluated,
            "ApprovalBound" => Self::ApprovalBound,
            "EffectPrepared" => Self::EffectPrepared,
            "EffectObserved" => Self::EffectObserved,
            "CommitSealed" => Self::CommitSealed,
            "RollbackPending" => Self::RollbackPending,
            "RollbackObserved" => Self::RollbackObserved,
            "RecoveryStarted" => Self::RecoveryStarted,
            "RecoveryCompleted" => Self::RecoveryCompleted,
            "SandboxDenied" => Self::SandboxDenied,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub run_id: String,
    pub step_id: String,
    pub actor: String,
    pub timestamp: String,
    pub policy_version: String,
    pub tool_version: String,
    pub parameter_hash: String,
    pub parent_event: Option<String>,
    pub summary: String,
}

impl AuditEvent {
    pub fn new(
        event_type: AuditEventType,
        run_id: impl Into<String>,
        step_id: impl Into<String>,
        actor: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            run_id: run_id.into(),
            step_id: step_id.into(),
            actor: actor.into(),
            timestamp: "1970-01-01T00:00:00Z".to_string(),
            policy_version: "policy-v0".to_string(),
            tool_version: "tool-v0".to_string(),
            parameter_hash: "unset".to_string(),
            parent_event: None,
            summary: redact_summary(&summary.into()),
        }
    }

    pub fn to_json_line(&self) -> String {
        let parent = self
            .parent_event
            .as_ref()
            .map(|value| format!("\"{}\"", escape_json(value)))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"event_type\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"actor\":\"{}\",\"timestamp\":\"{}\",\"policy_version\":\"{}\",\"tool_version\":\"{}\",\"parameter_hash\":\"{}\",\"parent_event\":{},\"summary\":\"{}\"}}",
            self.event_type.as_str(),
            escape_json(&self.run_id),
            escape_json(&self.step_id),
            escape_json(&self.actor),
            escape_json(&self.timestamp),
            escape_json(&self.policy_version),
            escape_json(&self.tool_version),
            escape_json(&self.parameter_hash),
            parent,
            escape_json(&self.summary)
        )
    }
}

#[derive(Debug)]
pub struct AuditJournal {
    path: PathBuf,
}

impl AuditJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, event: &AuditEvent) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", event.to_json_line())?;
        file.sync_all()?;
        Ok(())
    }

    pub fn event_lines(&self) -> std::io::Result<Vec<String>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        reader.lines().collect()
    }

    pub fn latest_run(&self) -> std::io::Result<Option<String>> {
        Ok(self
            .event_lines()?
            .iter()
            .rev()
            .find_map(|line| extract_json_string(line, "run_id")))
    }

    pub fn run_timeline(&self, run_id: &str) -> std::io::Result<Vec<String>> {
        Ok(self
            .event_lines()?
            .into_iter()
            .filter(|line| extract_json_string(line, "run_id").as_deref() == Some(run_id))
            .collect())
    }

    pub fn unresolved_effects(&self) -> std::io::Result<Vec<String>> {
        let lines = self.event_lines()?;
        let mut prepared = Vec::new();
        let mut sealed_steps = Vec::new();
        let mut rolled_back_steps = Vec::new();

        for line in &lines {
            let event_type = extract_json_string(line, "event_type");
            let step_id = extract_json_string(line, "step_id").unwrap_or_default();
            match event_type.as_deref() {
                Some("EffectPrepared") => prepared.push((step_id, line.clone())),
                Some("CommitSealed") => sealed_steps.push(step_id),
                Some("RollbackObserved") => rolled_back_steps.push(step_id),
                _ => {}
            }
        }

        Ok(prepared
            .into_iter()
            .filter(|(step_id, _)| {
                !sealed_steps.contains(step_id) && !rolled_back_steps.contains(step_id)
            })
            .map(|(_, line)| line)
            .collect())
    }
}

pub fn redact_summary(summary: &str) -> String {
    let mut output = Vec::new();
    for token in summary.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        let key = lower
            .split_once('=')
            .map(|(key, _)| key)
            .or_else(|| lower.split_once(':').map(|(key, _)| key));
        let key = key.map(|value| {
            value.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        });
        if matches!(key, Some("secret" | "password" | "token" | "apikey" | "api_key")) {
            output.push("[REDACTED]");
        } else {
            output.push(token);
        }
    }
    output.join(" ")
}

fn extract_json_string(line: &str, key: &str) -> Option<String> {
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
            "agentd-{name}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    #[test]
    fn appends_required_event_types_as_jsonl() {
        let journal = test_journal("append");
        let mut event = AuditEvent::new(
            AuditEventType::IntentReceived,
            "run-1",
            "step-1",
            "operator",
            "inspect service",
        );
        event.policy_version = "policy-v1".to_string();
        event.tool_version = "tool-v1".to_string();
        event.parameter_hash = "hash-1".to_string();
        journal.append(&event).expect("append event");
        let lines = journal.event_lines().expect("read lines");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"event_type\":\"IntentReceived\""));
        assert!(lines[0].contains("\"policy_version\":\"policy-v1\""));
        assert!(lines[0].contains("\"parameter_hash\":\"hash-1\""));
    }

    #[test]
    fn reports_unresolved_prepared_effect_after_restart() {
        let journal = test_journal("unresolved");
        journal
            .append(&AuditEvent::new(
                AuditEventType::EffectPrepared,
                "run-2",
                "step-2",
                "operator",
                "prepared restart",
            ))
            .expect("append prepared");

        let reopened = AuditJournal::new(journal.path().to_path_buf());
        let unresolved = reopened.unresolved_effects().expect("query unresolved");
        assert_eq!(unresolved.len(), 1);
        assert!(unresolved[0].contains("EffectPrepared"));
    }

    #[test]
    fn sealed_effect_is_not_unresolved() {
        let journal = test_journal("sealed");
        journal
            .append(&AuditEvent::new(
                AuditEventType::EffectPrepared,
                "run-3",
                "step-3",
                "operator",
                "prepared write",
            ))
            .expect("append prepared");
        journal
            .append(&AuditEvent::new(
                AuditEventType::CommitSealed,
                "run-3",
                "step-3",
                "operator",
                "verified and sealed",
            ))
            .expect("append sealed");
        assert!(journal.unresolved_effects().expect("query").is_empty());
    }

    #[test]
    fn redacts_secret_like_summary_tokens() {
        let event = AuditEvent::new(
            AuditEventType::EffectPrepared,
            "run-4",
            "step-4",
            "operator",
            "using password=hunter2 token=abc public-data",
        );
        let line = event.to_json_line();
        assert!(!line.contains("hunter2"));
        assert!(!line.contains("token=abc"));
        assert!(line.contains("[REDACTED]"));
        assert!(line.contains("public-data"));
    }

    #[test]
    fn redaction_does_not_hide_non_secret_words_containing_token() {
        let event = AuditEvent::new(
            AuditEventType::PolicyEvaluated,
            "run-5",
            "step-5",
            "operator",
            "approval required for token=value",
        );
        let line = event.to_json_line();
        assert!(line.contains("approval required"));
        assert!(line.contains("for"));
        assert!(!line.contains("token=value"));
        assert!(line.contains("[REDACTED]"));
    }
}
