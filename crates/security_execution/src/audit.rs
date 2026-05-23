use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::escape_json;

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

    pub fn project_latest_runtime_run(&self) -> std::io::Result<Option<RuntimeAuditProjection>> {
        let Some(run_id) = self.latest_run()? else {
            return Ok(None);
        };
        self.project_runtime_run(&run_id)
    }

    pub fn project_runtime_run(
        &self,
        run_id: &str,
    ) -> std::io::Result<Option<RuntimeAuditProjection>> {
        let mut events = Vec::new();
        let mut warnings = Vec::new();
        for (index, line) in self.event_lines()?.into_iter().enumerate() {
            if extract_json_string(&line, "run_id").as_deref() != Some(run_id) {
                continue;
            }
            match RuntimeAuditEventProjection::from_line(&line) {
                Ok(event) => events.push(event),
                Err(reason) => warnings.push(format!("line {} skipped: {reason}", index + 1)),
            }
        }
        if events.is_empty() && warnings.is_empty() {
            return Ok(None);
        }
        Ok(Some(RuntimeAuditProjection::from_events(
            run_id.to_string(),
            events,
            warnings,
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAuditProjection {
    pub run_id: String,
    pub plan_id: Option<String>,
    pub plan_hash: Option<String>,
    pub planner_metadata: Option<String>,
    pub steps: Vec<RuntimeAuditStepProjection>,
    pub warnings: Vec<String>,
}

impl RuntimeAuditProjection {
    fn from_events(
        run_id: String,
        events: Vec<RuntimeAuditEventProjection>,
        warnings: Vec<String>,
    ) -> Self {
        let mut projection = Self {
            run_id,
            plan_id: None,
            plan_hash: None,
            planner_metadata: None,
            steps: Vec::new(),
            warnings,
        };
        for event in events {
            if event.event_type == AuditEventType::PlanFrozen.as_str() {
                projection.plan_id = summary_value(&event.summary, "plan_id");
                projection.plan_hash = summary_value(&event.summary, "plan_hash")
                    .or_else(|| non_empty_metadata(&event.parameter_hash));
                projection.planner_metadata = Some(event.summary.clone());
            }
            let step = projection.step_mut(&event.step_id);
            step.absorb_event(event);
        }
        projection
    }

    fn step_mut(&mut self, step_id: &str) -> &mut RuntimeAuditStepProjection {
        if let Some(index) = self.steps.iter().position(|step| step.step_id == step_id) {
            return &mut self.steps[index];
        }
        self.steps.push(RuntimeAuditStepProjection::new(step_id));
        self.steps.last_mut().expect("just pushed step")
    }

    pub fn event_count(&self) -> usize {
        self.steps.iter().map(|step| step.events.len()).sum()
    }

    pub fn to_json(&self) -> String {
        let steps = self
            .steps
            .iter()
            .map(RuntimeAuditStepProjection::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"run_id\":\"{}\",\"plan_id\":{},\"plan_hash\":{},\"planner_metadata\":{},\"event_count\":{},\"warnings\":{},\"steps\":[{}]}}",
            escape_json(&self.run_id),
            optional_json(self.plan_id.as_deref()),
            optional_json(self.plan_hash.as_deref()),
            optional_json(self.planner_metadata.as_deref()),
            self.event_count(),
            string_array_json(&self.warnings),
            steps
        )
    }

    pub fn to_cli_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "run={} plan_id={} plan_hash={} events={} warnings={}",
            self.run_id,
            self.plan_id.as_deref().unwrap_or("-"),
            self.plan_hash.as_deref().unwrap_or("-"),
            self.event_count(),
            self.warnings.len()
        )];
        lines.extend(self.steps.iter().map(RuntimeAuditStepProjection::to_cli_line));
        lines
    }

    pub fn to_cli_text(&self) -> String {
        self.to_cli_lines().join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAuditStepProjection {
    pub step_id: String,
    pub status: String,
    pub policy_summary: Option<String>,
    pub approval_summary: Option<String>,
    pub lease_id: Option<String>,
    pub sandbox_profile_summary: Option<String>,
    pub effect_state: String,
    pub observation_summary: Option<String>,
    pub observation_source: Option<String>,
    pub observation_trust: Option<String>,
    pub verification_summary: Option<String>,
    pub rollback_summary: Option<String>,
    pub recovery_summary: Option<String>,
    pub final_summary: Option<String>,
    pub effect_prepared: bool,
    pub effect_observed: bool,
    pub commit_sealed: bool,
    pub events: Vec<RuntimeAuditEventProjection>,
}

impl RuntimeAuditStepProjection {
    fn new(step_id: &str) -> Self {
        Self {
            step_id: step_id.to_string(),
            status: "pending".to_string(),
            policy_summary: None,
            approval_summary: None,
            lease_id: None,
            sandbox_profile_summary: None,
            effect_state: "none".to_string(),
            observation_summary: None,
            observation_source: None,
            observation_trust: None,
            verification_summary: None,
            rollback_summary: None,
            recovery_summary: None,
            final_summary: None,
            effect_prepared: false,
            effect_observed: false,
            commit_sealed: false,
            events: Vec::new(),
        }
    }

    fn absorb_event(&mut self, event: RuntimeAuditEventProjection) {
        let summary = redact_summary(&event.summary);
        self.final_summary = Some(summary.clone());
        match event.event_type.as_str() {
            "IntentReceived" => {
                self.status = "accepted".to_string();
            }
            "PlanFrozen" => {
                self.status = "planned".to_string();
            }
            "PolicyEvaluated" => {
                self.policy_summary = Some(summary.clone());
                self.lease_id = self.lease_id.clone().or_else(|| summary_value(&summary, "lease_id"));
                if summary.contains("decision=deny") {
                    self.status = "denied".to_string();
                } else if summary.contains("pause-for-approval") {
                    self.status = "paused".to_string();
                } else {
                    self.status = "policy-evaluated".to_string();
                }
            }
            "ApprovalBound" => {
                self.approval_summary = Some(summary.clone());
                self.lease_id = self.lease_id.clone().or_else(|| summary_value(&summary, "lease_id"));
                if summary.contains("approval denied") {
                    self.status = "denied".to_string();
                } else {
                    self.status = "approval-bound".to_string();
                }
            }
            "EffectPrepared" => {
                self.effect_prepared = true;
                self.effect_state = "prepared".to_string();
                self.status = "prepared".to_string();
            }
            "EffectObserved" => {
                self.effect_observed = true;
                self.effect_state = "observed".to_string();
                self.status = "observed".to_string();
                self.observation_summary = Some(summary.clone());
                self.observation_source = summary_value(&summary, "source");
                self.observation_trust = summary_value(&summary, "trust");
            }
            "CommitSealed" => {
                self.commit_sealed = true;
                self.effect_state = "sealed".to_string();
                self.status = "sealed".to_string();
                self.verification_summary = Some(format!("success: {summary}"));
            }
            "RollbackPending" => {
                self.effect_state = "rollback-pending".to_string();
                self.status = "rollback-pending".to_string();
                self.rollback_summary = Some(summary.clone());
                self.verification_summary = Some(format!("failed: {summary}"));
            }
            "RollbackObserved" => {
                self.effect_state = "rolled-back".to_string();
                self.status = "rolled-back".to_string();
                self.rollback_summary = Some(summary.clone());
            }
            "RecoveryStarted" => {
                self.status = "recovering".to_string();
                self.recovery_summary = Some(format!("source=run-store+audit {summary}"));
            }
            "RecoveryCompleted" => {
                self.status = "recovered".to_string();
                self.recovery_summary = Some(format!("source=run-store+audit {summary}"));
            }
            "SandboxDenied" => {
                self.status = "denied".to_string();
                self.sandbox_profile_summary = Some(summary.clone());
            }
            _ => {}
        }
        self.events.push(event);
    }

    pub fn to_json(&self) -> String {
        let events = self
            .events
            .iter()
            .map(RuntimeAuditEventProjection::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"step_id\":\"{}\",\"status\":\"{}\",\"policy_summary\":{},\"approval_summary\":{},\"lease_id\":{},\"sandbox_profile_summary\":{},\"effect_state\":\"{}\",\"observation_summary\":{},\"observation_source\":{},\"observation_trust\":{},\"verification_summary\":{},\"rollback_summary\":{},\"recovery_summary\":{},\"final_summary\":{},\"effect_prepared\":{},\"effect_observed\":{},\"commit_sealed\":{},\"events\":[{}]}}",
            escape_json(&self.step_id),
            escape_json(&self.status),
            optional_json(self.policy_summary.as_deref()),
            optional_json(self.approval_summary.as_deref()),
            optional_json(self.lease_id.as_deref()),
            optional_json(self.sandbox_profile_summary.as_deref()),
            escape_json(&self.effect_state),
            optional_json(self.observation_summary.as_deref()),
            optional_json(self.observation_source.as_deref()),
            optional_json(self.observation_trust.as_deref()),
            optional_json(self.verification_summary.as_deref()),
            optional_json(self.rollback_summary.as_deref()),
            optional_json(self.recovery_summary.as_deref()),
            optional_json(self.final_summary.as_deref()),
            self.effect_prepared,
            self.effect_observed,
            self.commit_sealed,
            events
        )
    }

    pub fn to_cli_line(&self) -> String {
        format!(
            "step={} status={} policy={} approval={} lease={} sandbox={} effect={} observation={} verification={} recovery={} final={}",
            self.step_id,
            self.status,
            self.policy_summary.as_deref().unwrap_or("-"),
            self.approval_summary.as_deref().unwrap_or("-"),
            self.lease_id.as_deref().unwrap_or("-"),
            self.sandbox_profile_summary.as_deref().unwrap_or("-"),
            self.effect_state,
            observation_cli(self),
            self.verification_summary.as_deref().unwrap_or("-"),
            self.recovery_summary.as_deref().unwrap_or("-"),
            self.final_summary.as_deref().unwrap_or("-")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAuditEventProjection {
    pub event_type: String,
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

impl RuntimeAuditEventProjection {
    fn from_line(line: &str) -> Result<Self, String> {
        let event_type = extract_json_string(line, "event_type")
            .ok_or_else(|| "missing event_type".to_string())?;
        Ok(Self {
            event_type,
            run_id: extract_json_string(line, "run_id")
                .ok_or_else(|| "missing run_id".to_string())?,
            step_id: extract_json_string(line, "step_id")
                .ok_or_else(|| "missing step_id".to_string())?,
            actor: extract_json_string(line, "actor").unwrap_or_default(),
            timestamp: extract_json_string(line, "timestamp").unwrap_or_default(),
            policy_version: extract_json_string(line, "policy_version").unwrap_or_default(),
            tool_version: extract_json_string(line, "tool_version").unwrap_or_default(),
            parameter_hash: extract_json_string(line, "parameter_hash").unwrap_or_default(),
            parent_event: extract_json_string(line, "parent_event"),
            summary: redact_summary(
                &extract_json_string(line, "summary")
                    .ok_or_else(|| "missing summary".to_string())?,
            ),
        })
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"event_type\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"actor\":\"{}\",\"timestamp\":\"{}\",\"policy_version\":\"{}\",\"tool_version\":\"{}\",\"parameter_hash\":\"{}\",\"parent_event\":{},\"summary\":\"{}\"}}",
            escape_json(&self.event_type),
            escape_json(&self.run_id),
            escape_json(&self.step_id),
            escape_json(&self.actor),
            escape_json(&self.timestamp),
            escape_json(&self.policy_version),
            escape_json(&self.tool_version),
            escape_json(&self.parameter_hash),
            optional_json(self.parent_event.as_deref()),
            escape_json(&self.summary)
        )
    }
}

pub fn redact_summary(summary: &str) -> String {
    let mut output = Vec::new();
    for token in summary.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if lower.starts_with("secret://") {
            output.push(token);
            continue;
        }
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

fn observation_cli(step: &RuntimeAuditStepProjection) -> String {
    match (
        step.observation_source.as_deref(),
        step.observation_trust.as_deref(),
        step.observation_summary.as_deref(),
    ) {
        (None, None, None) => "-".to_string(),
        (source, trust, summary) => format!(
            "source={} trust={} summary={}",
            source.unwrap_or("-"),
            trust.unwrap_or("-"),
            summary.unwrap_or("-")
        ),
    }
}

fn summary_value(summary: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    summary
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
        .map(|value| {
            value
                .trim_matches(|ch: char| {
                    !ch.is_ascii_alphanumeric() && !matches!(ch, ':' | '/' | '_' | '-' | '.')
                })
                .to_string()
        })
        .filter(|value| !value.is_empty())
}

fn non_empty_metadata(value: &str) -> Option<String> {
    if value.is_empty() || value == "unset" {
        None
    } else {
        Some(value.to_string())
    }
}

fn optional_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn string_array_json(values: &[String]) -> String {
    let items = values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

fn extract_json_string(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub fn extract_json_string_for_tests(line: &str, key: &str) -> Option<String> {
    extract_json_string(line, key)
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

    fn event(
        event_type: AuditEventType,
        run_id: &str,
        step_id: &str,
        summary: &str,
    ) -> AuditEvent {
        AuditEvent::new(event_type, run_id, step_id, "operator", summary)
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

    #[test]
    fn projects_latest_runtime_run_with_stable_step_order() {
        let journal = test_journal("runtime-projection");
        journal
            .append(&event(
                AuditEventType::IntentReceived,
                "run-a",
                "intent",
                "intent accepted plan_id=plan-a requested_outcome=recover-nginx",
            ))
            .expect("intent");
        let mut plan = event(
            AuditEventType::PlanFrozen,
            "run-a",
            "plan",
            "plan frozen plan_id=plan-a plan_hash=hash-a",
        );
        plan.parameter_hash = "hash-a".to_string();
        journal.append(&plan).expect("plan");
        journal
            .append(&event(
                AuditEventType::PolicyEvaluated,
                "run-a",
                "inspect",
                "decision=allow tool=svc.status resource=nginx risk=read-only reason=diagnostic",
            ))
            .expect("policy");
        journal
            .append(&event(
                AuditEventType::EffectPrepared,
                "run-a",
                "inspect",
                "prepared tool=svc.status risk=read-only parameter_hash=hash-inspect",
            ))
            .expect("prepared");
        journal
            .append(&event(
                AuditEventType::EffectObserved,
                "run-a",
                "inspect",
                "observation processed source=semantic-tool trust=sandboxed-tool summary=status-active",
            ))
            .expect("observed");
        journal
            .append(&event(
                AuditEventType::CommitSealed,
                "run-a",
                "inspect",
                "commit sealed tool=svc.status commit_id=commit-1",
            ))
            .expect("sealed");

        let projection = journal
            .project_latest_runtime_run()
            .expect("projection")
            .expect("latest run");
        assert_eq!(projection.run_id, "run-a");
        assert_eq!(projection.plan_id.as_deref(), Some("plan-a"));
        assert_eq!(projection.plan_hash.as_deref(), Some("hash-a"));
        assert_eq!(projection.event_count(), 6);
        assert_eq!(projection.steps[0].step_id, "intent");
        assert_eq!(projection.steps[1].step_id, "plan");
        assert_eq!(projection.steps[2].step_id, "inspect");
        assert_eq!(projection.steps[2].status, "sealed");
        assert_eq!(
            projection.steps[2].observation_trust.as_deref(),
            Some("sandboxed-tool")
        );
        let json = projection.to_json();
        assert!(json.contains("\"effect_state\":\"sealed\""));
        assert!(json.contains("\"observation_source\":\"semantic-tool\""));
        let cli = projection.to_cli_text();
        assert!(cli.contains("run=run-a"));
        assert!(cli.contains("step=inspect status=sealed"));
    }

    #[test]
    fn projection_explains_denied_step_without_prepared_effect() {
        let journal = test_journal("runtime-denied");
        journal
            .append(&event(
                AuditEventType::PolicyEvaluated,
                "run-denied",
                "restart",
                "decision=deny tool=svc.restart resource=nginx risk=never reason=approval-missing",
            ))
            .expect("policy denied");
        journal
            .append(&event(
                AuditEventType::ApprovalBound,
                "run-denied",
                "restart",
                "approval denied reason=operator declined",
            ))
            .expect("approval denied");

        let projection = journal
            .project_runtime_run("run-denied")
            .expect("projection")
            .expect("run projection");
        assert_eq!(projection.steps.len(), 1);
        let step = &projection.steps[0];
        assert_eq!(step.status, "denied");
        assert!(!step.effect_prepared);
        assert_eq!(step.effect_state, "none");
        assert!(step.policy_summary.as_deref().unwrap().contains("decision=deny"));
        assert!(step.to_cli_line().contains("approval denied"));
    }

    #[test]
    fn projection_preserves_secret_handles_and_redacts_secret_values() {
        let journal = test_journal("runtime-redaction");
        journal
            .append(&event(
                AuditEventType::EffectObserved,
                "run-secret",
                "secret-step",
                "using secret://prod/db password=hunter2 token=abc123",
            ))
            .expect("secret observation");

        let projection = journal
            .project_runtime_run("run-secret")
            .expect("projection")
            .expect("run projection");
        let json = projection.to_json();
        assert!(json.contains("secret://prod/db"));
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("token=abc123"));
    }

    #[test]
    fn projection_records_recovery_source_and_malformed_line_warning() {
        let journal = test_journal("runtime-recovery");
        journal
            .append(&event(
                AuditEventType::RecoveryStarted,
                "run-recover",
                "restart",
                "recovery started from state=Executing",
            ))
            .expect("recovery started");
        journal
            .append(&event(
                AuditEventType::RecoveryCompleted,
                "run-recover",
                "restart",
                "recovery completed status=ReconcileEffects",
            ))
            .expect("recovery completed");
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(journal.path())
                .expect("open journal");
            writeln!(
                file,
                "{{\"run_id\":\"run-recover\",\"step_id\":\"broken\",\"summary\":\"missing event type\"}}"
            )
            .expect("write malformed line");
        }

        let projection = journal
            .project_runtime_run("run-recover")
            .expect("projection")
            .expect("run projection");
        assert_eq!(projection.steps[0].status, "recovered");
        assert!(projection.steps[0]
            .recovery_summary
            .as_deref()
            .unwrap()
            .contains("source=run-store+audit"));
        assert_eq!(projection.warnings.len(), 1);
        assert!(projection.warnings[0].contains("missing event_type"));
    }
}
