use std::collections::BTreeMap;

use crate::api::escape_json;
use crate::audit::redact_summary;
use crate::runtime_contracts::contains_secret_value;

use super::workflow_catalog::{WorkflowCatalogItem, WorkflowCatalogProjection};

pub const LAUNCH_INTENT_PREVIEW_SCHEMA_VERSION: &str = "agentos.tui-launch-intent-preview.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchIntentPreview {
    pub schema_version: &'static str,
    pub workflow_id: String,
    pub workflow_status: String,
    pub risk: String,
    pub typed_intent: String,
    pub workflow_authority_path: String,
    pub approval_requirements: Vec<String>,
    pub rollback_expectation: String,
    pub evidence_outputs: Vec<String>,
    pub input_summary: String,
    pub redaction_applied: bool,
}

impl LaunchIntentPreview {
    pub fn collect(
        catalog: &WorkflowCatalogProjection,
        workflow_id: &str,
        input_tokens: &[String],
    ) -> Result<Self, LaunchPreviewError> {
        let workflow = catalog
            .workflows
            .iter()
            .find(|workflow| workflow.id == workflow_id)
            .ok_or_else(|| {
                LaunchPreviewError::new(format!("workflow id not found: {workflow_id}"))
            })?;
        let inputs = LaunchInputSet::parse(input_tokens)?;
        Ok(Self {
            schema_version: LAUNCH_INTENT_PREVIEW_SCHEMA_VERSION,
            workflow_id: workflow.id.to_string(),
            workflow_status: workflow.status.clone(),
            risk: workflow.risk.to_string(),
            typed_intent: build_typed_intent(workflow, &inputs),
            workflow_authority_path: workflow.authority_path.clone(),
            approval_requirements: workflow.approval_requirements.clone(),
            rollback_expectation: workflow.rollback_expectation.to_string(),
            evidence_outputs: workflow.evidence_outputs.clone(),
            input_summary: inputs.summary(),
            redaction_applied: inputs.redaction_applied(),
        })
    }

    pub fn render(&self) -> String {
        [
            "TUI Launch Intent Preview".to_string(),
            format!(
                "launch_preview schema={} workflow={} status={} risk={} input_status=accepted dispatch_required=true explicit_dispatch_required=true direct_execute=false plan_spec_created=false side_effects_prepared=false deterministic=true redaction=secret-values-redacted redaction_applied={}",
                self.schema_version,
                escape_json(&self.workflow_id),
                escape_json(&self.workflow_status),
                escape_json(&self.risk),
                self.redaction_applied
            ),
            format!(
                "typed_intent=\"{}\"",
                escape_json(&redact_summary(&self.typed_intent))
            ),
            "authority_path=\"AgentCore planner -> SecurityExecutionEngine -> approval -> rollback\"".to_string(),
            format!(
                "workflow_authority_path=\"{}\"",
                escape_json(&redact_summary(&self.workflow_authority_path))
            ),
            format!(
                "approval_requirements=\"{}\"",
                escape_json(&redact_summary(&self.approval_requirements.join("|")))
            ),
            format!(
                "rollback_expectation=\"{}\"",
                escape_json(&redact_summary(&self.rollback_expectation))
            ),
            format!(
                "evidence_outputs=\"{}\"",
                escape_json(&redact_summary(&self.evidence_outputs.join("|")))
            ),
            format!(
                "input_summary=\"{}\"",
                escape_json(&redact_summary(&self.input_summary))
            ),
            format!(
                "dispatch_after_preview=\"{}\"",
                escape_json(&redact_summary(&self.typed_intent))
            ),
        ]
        .join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPreviewError {
    pub reason: String,
}

impl LaunchPreviewError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaunchInput {
    key: String,
    value: String,
    redacted_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaunchInputSet {
    inputs: Vec<LaunchInput>,
}

impl LaunchInputSet {
    fn parse(tokens: &[String]) -> Result<Self, LaunchPreviewError> {
        let mut by_key = BTreeMap::new();
        for token in tokens {
            reject_unsafe_launch_fragment(token)?;
            if contains_secret_value(token) {
                return Err(LaunchPreviewError::new(
                    "secret-like launch input must use a secret:// handle or be omitted",
                ));
            }
            let Some((key, value)) = token.split_once('=') else {
                return Err(LaunchPreviewError::new(
                    "launch.preview inputs must use key=value form",
                ));
            };
            validate_key(key)?;
            validate_value(value)?;
            if by_key.contains_key(key) {
                return Err(LaunchPreviewError::new(format!(
                    "duplicate launch input key: {key}"
                )));
            }
            by_key.insert(
                key.to_string(),
                LaunchInput {
                    key: key.to_string(),
                    value: value.to_string(),
                    redacted_value: redact_launch_value(key, value),
                },
            );
        }
        Ok(Self {
            inputs: by_key.into_values().collect(),
        })
    }

    fn summary(&self) -> String {
        if self.inputs.is_empty() {
            return "-".to_string();
        }
        self.inputs
            .iter()
            .map(|input| format!("{}={}", input.key, input.redacted_value))
            .collect::<Vec<_>>()
            .join("|")
    }

    fn intent_clauses(&self) -> Vec<String> {
        self.inputs
            .iter()
            .map(|input| format!("input.{}={}", input.key, input.redacted_value))
            .collect()
    }

    fn redaction_applied(&self) -> bool {
        self.inputs
            .iter()
            .any(|input| input.value != input.redacted_value)
    }

    fn display_value(&self, key: &str) -> Option<&str> {
        self.inputs
            .iter()
            .find(|input| input.key == key)
            .map(|input| input.redacted_value.as_str())
    }
}

pub(crate) fn validate_launch_preview_inputs(tokens: &[String]) -> Result<(), LaunchPreviewError> {
    LaunchInputSet::parse(tokens).map(|_| ())
}

fn build_typed_intent(workflow: &WorkflowCatalogItem, inputs: &LaunchInputSet) -> String {
    let mut intent = match workflow.id {
        "service.recovery" => format!(
            "intent.submit recover {} service",
            inputs.display_value("service").unwrap_or("nginx")
        ),
        "package.install" => format!(
            "intent.submit install {} package through isolated validation",
            inputs
                .display_value("package_identity")
                .unwrap_or("package")
        ),
        "content.inspect" => "intent.submit inspect pinned untrusted content".to_string(),
        "rootfs.update" => "intent.submit stage signed rootfs update for inactive slot".to_string(),
        "support.bundle" => "intent.submit prepare redacted support bundle export".to_string(),
        "aom.activation.preview" => format!(
            "intent.submit preview aom activation {}",
            inputs
                .display_value("coordinate")
                .unwrap_or("agentos:workflow-pack/agentos/service-recovery@1.0.0")
        ),
        _ => "intent.submit launch selected capability".to_string(),
    };
    let clauses = inputs.intent_clauses();
    if !clauses.is_empty() {
        intent.push(' ');
        intent.push_str(&clauses.join(" "));
    }
    intent
}

fn validate_key(key: &str) -> Result<(), LaunchPreviewError> {
    if key.is_empty() {
        return Err(LaunchPreviewError::new("launch input key is empty"));
    }
    if matches!(
        key,
        "cmd" | "command" | "exec" | "shell" | "powershell" | "pwsh" | "bash" | "sh"
    ) {
        return Err(LaunchPreviewError::new(format!(
            "unsafe launch input key is not accepted: {key}"
        )));
    }
    if !key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(LaunchPreviewError::new(format!(
            "launch input key contains unsupported characters: {key}"
        )));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<(), LaunchPreviewError> {
    if value.is_empty() {
        return Err(LaunchPreviewError::new("launch input value is empty"));
    }
    reject_unsafe_launch_fragment(value)
}

fn reject_unsafe_launch_fragment(value: &str) -> Result<(), LaunchPreviewError> {
    for forbidden in ["|", ">", "<", ";", "&&", "||", "$(", "`"] {
        if value.contains(forbidden) {
            return Err(LaunchPreviewError::new(format!(
                "shell-like syntax is not accepted in launch preview input: {forbidden}"
            )));
        }
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("shell.exec") {
        return Err(LaunchPreviewError::new(
            "direct shell.exec authority is not accepted in launch preview input",
        ));
    }
    if lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|word| matches!(word, "powershell" | "pwsh" | "cmd" | "bash" | "sh" | "sudo"))
    {
        return Err(LaunchPreviewError::new(
            "host shell command names are not accepted in launch preview input",
        ));
    }
    Ok(())
}

fn redact_launch_value(key: &str, value: &str) -> String {
    let lower_key = key.to_ascii_lowercase();
    let lower_value = value.to_ascii_lowercase();
    if matches!(
        lower_key.as_str(),
        "secret" | "password" | "token" | "apikey" | "api_key" | "access_token" | "credential"
    ) || lower_value.starts_with("secret://")
        || lower_value.contains("secret://")
    {
        return "[REDACTED]".to_string();
    }
    redact_summary(value)
}
