use std::path::Path;

use crate::api::escape_json;
use crate::audit::redact_summary;
use crate::operator_projection::OperatorProjection;
use crate::support_bundle::SupportBundleProjection;

use super::degraded_state::{DegradedStateExplainer, safe_evidence_path};
use super::snapshot::ProjectionSnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportConsolePanel {
    pub status: String,
    pub bundle_path: String,
    pub last_export_path: String,
    pub export_written: bool,
    pub bundle: SupportBundleProjection,
    pub operator: OperatorProjection,
    pub snapshot: ProjectionSnapshot,
}

impl SupportConsolePanel {
    pub fn collect(
        export_written: bool,
        bundle_path: &Path,
        bundle: SupportBundleProjection,
        operator: OperatorProjection,
        snapshot: ProjectionSnapshot,
    ) -> Self {
        let bundle_path = bundle_path.display().to_string();
        let last_export_path = if export_written || Path::new(&bundle_path).is_file() {
            bundle_path.clone()
        } else {
            "-".to_string()
        };
        Self {
            status: if export_written {
                "exported".to_string()
            } else {
                "ready".to_string()
            },
            bundle_path,
            last_export_path,
            export_written,
            bundle,
            operator,
            snapshot,
        }
    }

    pub fn render(&self) -> String {
        let degraded_sources = self.snapshot_degraded_sources().join("|");
        let display_bundle_path = safe_evidence_path(&self.bundle_path);
        let display_last_export_path = safe_evidence_path(&self.last_export_path);
        let degraded_explainer = DegradedStateExplainer::collect(
            &self.snapshot,
            &self.bundle,
            &self.operator,
            &self.bundle_path,
        );
        let mut lines = vec![
            "TUI Support Bundle".to_string(),
            "TUI Support Console".to_string(),
            format!(
                "panel=support-console status={} readiness={} export_path=\"{}\" last_export_path=\"{}\" export_written={} typed_export=\"support.bundle export\" preview_required=true bundle_id={} deterministic={} redaction={} includes_raw_secret={} audit_range=\"{}\" audit_hash_chain={}",
                self.status,
                self.bundle_readiness(),
                escape_json(&display_bundle_path),
                escape_json(&display_last_export_path),
                self.export_written,
                self.bundle.manifest.bundle_id,
                self.bundle.deterministic,
                self.bundle.manifest.redaction_status,
                self.bundle.manifest.includes_raw_secret,
                escape_json(&self.bundle.manifest.audit_event_range),
                self.bundle.manifest.audit_hash_chain
            ),
            format!(
                "runtime_health state={} loop_status={} planner={} run_mode={} normal_shell_available={} direct_model_execution_allowed={} external_llm_required={} network_required={} runtime_authority=\"{}\"",
                self.operator.runtime.state,
                self.bundle.runtime.loop_status,
                self.operator.runtime.planner_mode,
                self.operator.runtime.run_mode,
                self.bundle.runtime.normal_shell_available,
                self.bundle.runtime.model_output_direct_execution_allowed,
                self.bundle.runtime.external_llm_required,
                self.bundle.runtime.network_required,
                escape_json(self.bundle.runtime.runtime_authority)
            ),
            format!(
                "audit_status local_authoritative=true remote_mirror_status={} remote_policy={} remote_authoritative_for_recovery=false non_local_side_effects_allowed={} seal={} events={} prepared={} sealed={} rollback_pending={} unresolved_effects={} warnings={}",
                self.operator.audit.remote_mirror_status,
                self.operator
                    .audit
                    .remote_mirror_failure_policy
                    .as_deref()
                    .unwrap_or("-"),
                self.operator
                    .audit
                    .remote_mirror_non_local_side_effects_allowed,
                self.operator.audit.audit_seal_status,
                self.operator.audit.event_count,
                self.operator.audit.effect_prepared_count,
                self.operator.audit.commit_sealed_count,
                self.operator.audit.rollback_pending_count,
                self.operator.audit.unresolved_effects,
                self.operator.audit.warning_count
            ),
            format!(
                "ecosystem_state status={} offline_baseline={} registry_status={} registry_freshness={} active_set_status={} active_artifacts={} replay_status={} revocation_status={} activation_authority=\"{}\" resolver_owner=\"agent_core::ecosystem\" agentd_resolver_logic={} private_key_paths_included={} network_required={}",
                self.operator.ecosystem.activation_status,
                self.bundle.ecosystem.offline_baseline_status,
                self.bundle.ecosystem.registry_snapshot_status,
                self.bundle.ecosystem.registry_snapshot_freshness,
                self.bundle.ecosystem.active_set_status,
                self.bundle.ecosystem.active_artifact_count,
                self.bundle.ecosystem.replay_status,
                self.bundle.ecosystem.revocation_status,
                escape_json(self.bundle.ecosystem.activation_authority),
                self.bundle.ecosystem.agentd_resolver_logic,
                self.bundle.ecosystem.private_key_paths_included,
                self.bundle.ecosystem.network_required
            ),
            format!(
                "release_evidence status={} freshness={} degraded={} detail=\"{}\"",
                self.snapshot.release.status,
                self.snapshot.release.freshness,
                self.snapshot.release.degraded,
                escape_json(&redact_support_text(&self.snapshot.release.detail))
            ),
            format!(
                "degraded_state degraded={} sources={} support_degraded={} ecosystem_degraded={} recovery_degraded={} action=\"{}\" evidence_path=\"{}\"",
                self.snapshot.has_degraded_sources(),
                if degraded_sources.is_empty() {
                    "-".to_string()
                } else {
                    degraded_sources
                },
                self.snapshot.support.degraded,
                self.snapshot.ecosystem.degraded,
                self.snapshot.recovery.degraded,
                self.next_action(),
                escape_json(&display_bundle_path)
            ),
            format!(
                "remote_mirror status={} local_audit_authoritative={} remote_authoritative_for_recovery=false failure_policy={} non_local_side_effects_allowed={}",
                self.operator.audit.remote_mirror_status,
                true,
                self.operator
                    .audit
                    .remote_mirror_failure_policy
                    .as_deref()
                    .unwrap_or("-"),
                self.operator
                    .audit
                    .remote_mirror_non_local_side_effects_allowed
            ),
        ];
        lines.extend(degraded_explainer.render_lines());
        lines.push(self.bundle.to_json());
        lines.join("\n")
    }

    fn bundle_readiness(&self) -> &'static str {
        if self.bundle.manifest.includes_raw_secret
            || self.bundle.manifest.redaction_status != "secret-values-redacted"
        {
            "blocked-redaction"
        } else if self.bundle.runtime.loop_status == "needs-reconciliation"
            || self.bundle.recovery.requires_human_review
        {
            "ready-with-degraded-state"
        } else {
            "ready"
        }
    }

    fn next_action(&self) -> &'static str {
        if self.export_written {
            "inspect-exported-bundle"
        } else {
            "support.bundle export"
        }
    }

    fn snapshot_degraded_sources(&self) -> Vec<&'static str> {
        [
            &self.snapshot.runs,
            &self.snapshot.audit,
            &self.snapshot.approvals,
            &self.snapshot.recovery,
            &self.snapshot.support,
            &self.snapshot.ecosystem,
            &self.snapshot.release,
        ]
        .into_iter()
        .filter(|source| source.degraded)
        .map(|source| source.name)
        .collect()
    }
}

fn redact_support_text(value: &str) -> String {
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
