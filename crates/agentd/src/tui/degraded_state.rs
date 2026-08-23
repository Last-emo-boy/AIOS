use crate::api::escape_json;
use crate::audit::redact_summary;
use crate::operator_projection::OperatorProjection;
use crate::runtime_contracts::contains_secret_value;
use crate::support_bundle::SupportBundleProjection;

use super::snapshot::{ProjectionSnapshot, ProjectionSourceSnapshot};

pub const DEGRADED_EXPLAINER_SCHEMA_VERSION: &str = "agentos.tui-degraded-state-explainer.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedStateExplainer {
    pub schema_version: &'static str,
    pub baseline_operable: bool,
    pub optional_dependency_degraded: bool,
    pub normal_shell_available: bool,
    pub items: Vec<DegradedStateItem>,
}

impl DegradedStateExplainer {
    pub fn collect(
        snapshot: &ProjectionSnapshot,
        bundle: &SupportBundleProjection,
        operator: &OperatorProjection,
        support_bundle_path: &str,
    ) -> Self {
        let mut items = snapshot
            .degraded_sources()
            .into_iter()
            .map(|source| item_from_snapshot_source(source, bundle, operator, support_bundle_path))
            .collect::<Vec<_>>();

        if operator.audit.remote_mirror_status != "not-observed" {
            items.push(remote_mirror_item(operator));
        }

        let optional_dependency_degraded = items.iter().any(|item| item.optional_dependency);
        Self {
            schema_version: DEGRADED_EXPLAINER_SCHEMA_VERSION,
            baseline_operable: baseline_operable(bundle, operator),
            optional_dependency_degraded,
            normal_shell_available: bundle.runtime.normal_shell_available,
            items,
        }
    }

    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "degraded_explainer schema={} count={} baseline_operable={} optional_dependency_degraded={} normal_shell_available={} action_model=typed-command-only path_policy=safe-display redaction=secret-values-redacted",
            self.schema_version,
            self.items.len(),
            self.baseline_operable,
            self.optional_dependency_degraded,
            self.normal_shell_available
        )];
        lines.extend(
            self.items
                .iter()
                .enumerate()
                .map(|(index, item)| item.to_cli_line(index)),
        );
        lines
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedStateItem {
    pub source: &'static str,
    pub authority: String,
    pub cause: String,
    pub impact: String,
    pub next_action: String,
    pub evidence_path: String,
    pub optional_dependency: bool,
    pub baseline_blocking: bool,
}

impl DegradedStateItem {
    fn to_cli_line(&self, index: usize) -> String {
        format!(
            "degraded_item[{index}] source={} optional_dependency={} baseline_blocking={} authority=\"{}\" cause=\"{}\" impact=\"{}\" next_action=\"{}\" evidence_path=\"{}\"",
            self.source,
            self.optional_dependency,
            self.baseline_blocking,
            escape_json(&redact_degraded_text(&self.authority)),
            escape_json(&redact_degraded_text(&self.cause)),
            escape_json(&redact_degraded_text(&self.impact)),
            escape_json(&safe_typed_action(&self.next_action)),
            escape_json(&safe_evidence_path(&self.evidence_path))
        )
    }
}

pub fn safe_evidence_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path == "-" {
        return "-".to_string();
    }
    let mut display = path
        .replace('\\', "/")
        .replace(['\n', '\r', '\t'], " ");
    if display.to_ascii_lowercase().contains("secret://") {
        return "[REDACTED-PATH]".to_string();
    }
    if display.to_ascii_lowercase().starts_with("file://") {
        display = display.trim_start_matches("file://").to_string();
    }
    let redacted = redact_degraded_text(&display);
    if redacted != display
        || contains_secret_value(&redacted)
        || contains_private_path_hint(&redacted)
    {
        "[REDACTED-PATH]".to_string()
    } else {
        redacted
    }
}

fn item_from_snapshot_source(
    source: &ProjectionSourceSnapshot,
    bundle: &SupportBundleProjection,
    operator: &OperatorProjection,
    support_bundle_path: &str,
) -> DegradedStateItem {
    let (impact, next_action, evidence_path, baseline_blocking) = match source.name {
        "runs" => (
            "run state may be unavailable until AgentCore RunStore is readable",
            "dashboard.show".to_string(),
            operator
                .audit
                .latest_run_id
                .as_deref()
                .map(|run_id| format!("run-store:{run_id}"))
                .unwrap_or_else(|| "run-store:latest".to_string()),
            true,
        ),
        "audit" => (
            "operator decisions must wait for local audit evidence to be readable",
            "events.show 12".to_string(),
            operator
                .audit
                .journal_path
                .clone()
                .unwrap_or_else(|| "audit-journal:local".to_string()),
            true,
        ),
        "approvals" => (
            "approval controls stay read-only until exact audit binding is visible",
            "approvals.show latest".to_string(),
            operator
                .audit
                .latest_run_id
                .as_deref()
                .map(|run_id| format!("approval-binding:{run_id}"))
                .unwrap_or_else(|| "approval-binding:latest".to_string()),
            false,
        ),
        "recovery" => (
            "manual review or rollback reconciliation is required before more mutation",
            "recovery.show latest".to_string(),
            operator
                .audit
                .latest_run_id
                .as_deref()
                .map(|run_id| format!("audit:{run_id}"))
                .unwrap_or_else(|| "audit:latest".to_string()),
            false,
        ),
        "support" => (
            "support bundle should be exported for handoff with redacted local evidence",
            "support.bundle export".to_string(),
            support_bundle_path.to_string(),
            false,
        ),
        "ecosystem" => (
            "AOM activation remains gated until local pinned evidence is explainable",
            ecosystem_next_action(bundle),
            ecosystem_evidence_path(bundle),
            false,
        ),
        "release" => (
            "release evidence is incomplete; operators should export current support context",
            "support.bundle export".to_string(),
            ".workflow/artifacts/release".to_string(),
            false,
        ),
        _ => (
            "operator attention is required for this projection source",
            "dashboard.show".to_string(),
            source.name.to_string(),
            false,
        ),
    };

    DegradedStateItem {
        source: source.name,
        authority: source.authority.to_string(),
        cause: format!(
            "status={} freshness={} detail={}",
            source.status,
            source.freshness,
            redact_degraded_text(&source.detail)
        ),
        impact: impact.to_string(),
        next_action,
        evidence_path,
        optional_dependency: false,
        baseline_blocking,
    }
}

fn remote_mirror_item(operator: &OperatorProjection) -> DegradedStateItem {
    DegradedStateItem {
        source: "remote-mirror",
        authority: "SecurityExecutionEngine AuditJournal local projection".to_string(),
        cause: format!(
            "status={} policy={} remote_authoritative_for_recovery=false",
            operator.audit.remote_mirror_status,
            operator
                .audit
                .remote_mirror_failure_policy
                .as_deref()
                .unwrap_or("-")
        ),
        impact: "remote audit mirroring is degraded, but local audit remains recovery authority"
            .to_string(),
        next_action: "events.show 12".to_string(),
        evidence_path: operator
            .audit
            .latest_run_id
            .as_deref()
            .map(|run_id| format!("audit:{run_id}"))
            .or_else(|| operator.audit.journal_path.clone())
            .unwrap_or_else(|| "audit-journal:local".to_string()),
        optional_dependency: true,
        baseline_blocking: false,
    }
}

fn baseline_operable(bundle: &SupportBundleProjection, operator: &OperatorProjection) -> bool {
    operator.runtime.state == "running"
        && !bundle.manifest.includes_raw_secret
        && bundle.manifest.redaction_status == "secret-values-redacted"
        && !bundle.runtime.normal_shell_available
        && !bundle.runtime.model_output_direct_execution_allowed
        && !bundle.runtime.external_llm_required
        && !bundle.runtime.network_required
}

fn ecosystem_next_action(bundle: &SupportBundleProjection) -> String {
    bundle
        .ecosystem
        .active_artifacts
        .iter()
        .find(|coordinate| is_safe_coordinate(coordinate))
        .map(|coordinate| format!("aom.verify {coordinate}"))
        .unwrap_or_else(|| "aom.search".to_string())
}

fn ecosystem_evidence_path(bundle: &SupportBundleProjection) -> String {
    if bundle.ecosystem.active_set_status != "present" {
        bundle.ecosystem.active_set_path.clone()
    } else if bundle.ecosystem.replay_status != "passed" {
        bundle.ecosystem.replay_result_path.clone()
    } else {
        bundle.ecosystem.registry_snapshot_path.clone()
    }
}

fn is_safe_coordinate(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(char::is_whitespace)
        && !contains_secret_value(value)
        && !contains_unsafe_action_fragment(value)
}

fn safe_typed_action(action: &str) -> String {
    let action = action.trim();
    let safe_prefix = action == "dashboard.show"
        || action == "support.bundle export"
        || action == "recovery.show latest"
        || action == "events.show 12"
        || action == "approvals.show latest"
        || action == "aom.search"
        || (action.starts_with("aom.verify ")
            && is_safe_coordinate(&action["aom.verify ".len()..]));
    if safe_prefix && !contains_unsafe_action_fragment(action) && !contains_secret_value(action) {
        action.to_string()
    } else {
        "dashboard.show".to_string()
    }
}

fn contains_unsafe_action_fragment(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("file://")
        || lower.contains(" explorer")
        || lower.starts_with("explorer")
        || lower.contains(" powershell")
        || lower.starts_with("powershell")
        || lower.contains(" pwsh")
        || lower.starts_with("pwsh")
        || lower.contains(" cmd")
        || lower.starts_with("cmd")
        || lower.contains(" sh ")
        || lower.starts_with("sh ")
        || lower.contains(" open ")
        || lower.starts_with("open ")
}

fn contains_private_path_hint(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("begin openssh private key")
        || lower.contains("/.ssh/")
        || lower.contains("\\.ssh\\")
        || lower.contains("/id_rsa")
        || lower.contains("\\id_rsa")
}

fn redact_degraded_text(value: &str) -> String {
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
