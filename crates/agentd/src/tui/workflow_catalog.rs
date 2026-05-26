use crate::api::escape_json;
use crate::audit::redact_summary;

use super::capability_index::{CapabilityIndexItem, CapabilityIndexProjection};

pub const WORKFLOW_CATALOG_SCHEMA_VERSION: &str = "agentos.tui-workflow-catalog.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowCatalogProjection {
    pub schema_version: &'static str,
    pub read_only: bool,
    pub projection_controller_only: bool,
    pub direct_execution_allowed: bool,
    pub plan_spec_created: bool,
    pub baseline_local_only: bool,
    pub external_dependency_required: bool,
    pub workflows: Vec<WorkflowCatalogItem>,
}

impl WorkflowCatalogProjection {
    pub fn collect(capabilities: &CapabilityIndexProjection) -> Self {
        let workflows = workflow_specs()
            .into_iter()
            .map(|spec| {
                let capability = capabilities
                    .capabilities
                    .iter()
                    .find(|capability| capability.id == spec.capability_id);
                WorkflowCatalogItem::from_spec(spec, capability)
            })
            .collect::<Vec<_>>();
        Self {
            schema_version: WORKFLOW_CATALOG_SCHEMA_VERSION,
            read_only: true,
            projection_controller_only: true,
            direct_execution_allowed: false,
            plan_spec_created: false,
            baseline_local_only: true,
            external_dependency_required: false,
            workflows,
        }
    }

    pub fn render(&self, detail_id: Option<&str>) -> String {
        match detail_id {
            Some(detail_id) => self.render_detail(detail_id),
            None => self.render_list(),
        }
    }

    fn render_list(&self) -> String {
        let mut lines = self.header_lines();
        for category in [
            "service",
            "package",
            "content",
            "update",
            "support",
            "ecosystem",
        ] {
            let count = self
                .workflows
                .iter()
                .filter(|workflow| workflow.category == category)
                .count();
            lines.push(format!("workflow_group category={category} count={count}"));
        }
        lines.extend(
            self.workflows
                .iter()
                .enumerate()
                .map(|(index, workflow)| workflow.to_summary_line(index)),
        );
        lines.join("\n")
    }

    fn render_detail(&self, detail_id: &str) -> String {
        let mut lines = self.header_lines();
        let Some(workflow) = self
            .workflows
            .iter()
            .find(|workflow| workflow.id == detail_id)
        else {
            lines.push(format!(
                "workflow_detail missing=true id=\"{}\" reason=\"workflow id not found\" direct_execute=false plan_spec_created=false",
                escape_json(detail_id)
            ));
            return lines.join("\n");
        };
        lines.push(workflow.to_detail_line());
        lines.join("\n")
    }

    fn header_lines(&self) -> Vec<String> {
        vec![
            "TUI Workflow Catalog".to_string(),
            format!(
                "workflow_catalog schema={} read_only={} projection_controller_only={} direct_execution_allowed={} plan_spec_created={} baseline_local_only={} external_dependency_required={} workflow_count={} launch_model=typed-preview-only",
                self.schema_version,
                self.read_only,
                self.projection_controller_only,
                self.direct_execution_allowed,
                self.plan_spec_created,
                self.baseline_local_only,
                self.external_dependency_required,
                self.workflows.len()
            ),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowCatalogItem {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub capability_id: &'static str,
    pub status: String,
    pub risk: &'static str,
    pub input_schema: &'static str,
    pub approval_requirements: Vec<String>,
    pub rollback_expectation: &'static str,
    pub evidence_outputs: Vec<String>,
    pub local_only: bool,
    pub external_dependency_status: String,
    pub source: String,
    pub authority_path: String,
    pub launch_preview: String,
    pub unavailable_reason: String,
}

impl WorkflowCatalogItem {
    fn from_spec(spec: WorkflowSpec, capability: Option<&CapabilityIndexItem>) -> Self {
        let status = capability
            .map(|capability| capability.status.as_str().to_string())
            .unwrap_or_else(|| "unavailable".to_string());
        let source = capability
            .map(|capability| capability.source.clone())
            .unwrap_or_else(|| spec.source.to_string());
        let authority_path = capability
            .map(|capability| capability.authority_path.to_string())
            .unwrap_or_else(|| spec.authority_path.to_string());
        let unavailable_reason = capability
            .map(|capability| capability.unavailable_reason.clone())
            .unwrap_or_else(|| "capability index entry is missing".to_string());
        Self {
            id: spec.id,
            title: spec.title,
            category: spec.category,
            capability_id: spec.capability_id,
            status,
            risk: spec.risk,
            input_schema: spec.input_schema,
            approval_requirements: spec
                .approval_requirements
                .iter()
                .map(ToString::to_string)
                .collect(),
            rollback_expectation: spec.rollback_expectation,
            evidence_outputs: spec
                .evidence_outputs
                .iter()
                .map(ToString::to_string)
                .collect(),
            local_only: spec.local_only,
            external_dependency_status: spec.external_dependency_status.to_string(),
            source,
            authority_path,
            launch_preview: spec.launch_preview.to_string(),
            unavailable_reason,
        }
    }

    fn to_summary_line(&self, index: usize) -> String {
        format!(
            "workflow[{index}] id={} title=\"{}\" category={} status={} risk={} local_only={} external_dependency_status=\"{}\" launch_preview=\"{}\" authority_path=\"{}\" direct_execute=false plan_spec_created=false",
            self.id,
            escape_json(self.title),
            self.category,
            escape_json(&self.status),
            self.risk,
            self.local_only,
            escape_json(&redact_summary(&self.external_dependency_status)),
            escape_json(&redact_summary(&self.launch_preview)),
            escape_json(&redact_summary(&self.authority_path))
        )
    }

    fn to_detail_line(&self) -> String {
        format!(
            "workflow_detail id={} title=\"{}\" category={} status={} risk={} input_schema=\"{}\" approval_requirements=\"{}\" rollback_expectation=\"{}\" evidence_outputs=\"{}\" local_only={} external_dependency_status=\"{}\" source=\"{}\" authority_path=\"{}\" launch_preview=\"{}\" unavailable_reason=\"{}\" direct_execute=false plan_spec_created=false",
            self.id,
            escape_json(self.title),
            self.category,
            escape_json(&self.status),
            self.risk,
            escape_json(self.input_schema),
            escape_json(&self.approval_requirements.join("|")),
            escape_json(self.rollback_expectation),
            escape_json(&self.evidence_outputs.join("|")),
            self.local_only,
            escape_json(&redact_summary(&self.external_dependency_status)),
            escape_json(&redact_summary(&self.source)),
            escape_json(&redact_summary(&self.authority_path)),
            escape_json(&redact_summary(&self.launch_preview)),
            escape_json(&redact_summary(&self.unavailable_reason))
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkflowSpec {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    capability_id: &'static str,
    risk: &'static str,
    input_schema: &'static str,
    approval_requirements: &'static [&'static str],
    rollback_expectation: &'static str,
    evidence_outputs: &'static [&'static str],
    local_only: bool,
    external_dependency_status: &'static str,
    source: &'static str,
    authority_path: &'static str,
    launch_preview: &'static str,
}

fn workflow_specs() -> Vec<WorkflowSpec> {
    vec![
        WorkflowSpec {
            id: "service.recovery",
            title: "Service Recovery",
            category: "service",
            capability_id: "service.recovery",
            risk: "execute-with-confirmation",
            input_schema: "service=<name>; diagnostics=logs,status,http; approval_actor=operator",
            approval_requirements: &["exact approval token for svc.restart"],
            rollback_expectation: "service restart is recoverable through run-store and audit reconciliation",
            evidence_outputs: &[
                "audit.show latest",
                "recovery.show latest",
                "support.bundle status",
            ],
            local_only: true,
            external_dependency_status: "none; baseline local-only",
            source: "builtin:agent_core::service_recovery",
            authority_path: "AgentCore PlanRun + SecurityExecutionEngine",
            launch_preview: "palette.preview intent.submit recover nginx service",
        },
        WorkflowSpec {
            id: "package.install",
            title: "Package Install",
            category: "package",
            capability_id: "package.install",
            risk: "privileged-with-human-approval",
            input_schema: "package_identity; package_uri; package_digest; isolated_smoke_report; rollback_id",
            approval_requirements: &[
                "isolated validation",
                "rollback_id",
                "exact approval token for pkg.host.install",
            ],
            rollback_expectation: "host package promotion requires rollback id before host mutation",
            evidence_outputs: &[
                "audit.show latest",
                "events.show 12",
                "support.bundle status",
            ],
            local_only: true,
            external_dependency_status: "host package manager optional; baseline does not require it",
            source: "OperatorProjection.adapters.package_manager",
            authority_path: "AgentCore package workflow + SecurityExecutionEngine package adapter",
            launch_preview: "palette.preview intent.submit install package through isolated validation",
        },
        WorkflowSpec {
            id: "content.inspect",
            title: "Untrusted Content Inspection",
            category: "content",
            capability_id: "content.inspect",
            risk: "read-only-source-to-sink",
            input_schema: "source_uri; content_digest; max_bytes; content_id",
            approval_requirements: &[
                "source digest",
                "max byte limit",
                "source-to-sink policy check",
            ],
            rollback_expectation: "no host mutation; sanitized context only",
            evidence_outputs: &["audit.show latest", "events.show 12"],
            local_only: true,
            external_dependency_status: "network fetch optional; baseline accepts pinned local file content",
            source: "OperatorProjection.adapters.untrusted_content",
            authority_path: "AgentCore untrusted content workflow + source-to-sink policy",
            launch_preview: "palette.preview intent.submit inspect pinned untrusted content",
        },
        WorkflowSpec {
            id: "rootfs.update",
            title: "A/B Rootfs Update",
            category: "update",
            capability_id: "rootfs.update",
            risk: "privileged-with-human-approval",
            input_schema: "release_manifest_sha256; rootfs_sha256; provenance_sha256; signature_bundle_sha256; update_metadata_sha256; inactive_slot",
            approval_requirements: &[
                "signed update metadata",
                "inactive slot validation",
                "rollback evidence",
                "exact approval token for activation",
            ],
            rollback_expectation: "A/B slot activation requires rollback evidence and inactive slot validation",
            evidence_outputs: &[
                ".workflow/artifacts/release/provenance.json",
                ".workflow/artifacts/tui-replay/result.json",
                "support.bundle status",
            ],
            local_only: true,
            external_dependency_status: "QEMU optional for smoke; baseline evidence is local artifact projection",
            source: "OperatorProjection.update",
            authority_path: "AgentCore rootfs_update + SecurityExecutionEngine update gate",
            launch_preview: "palette.preview intent.submit stage signed rootfs update for inactive slot",
        },
        WorkflowSpec {
            id: "support.bundle",
            title: "Support Bundle Export",
            category: "support",
            capability_id: "support.bundle",
            risk: "read-only-export",
            input_schema: "run_id=latest; redaction=secret-values-redacted; audit_range",
            approval_requirements: &["redacted audit projection", "support bundle manifest"],
            rollback_expectation: "no runtime mutation; writes redacted local evidence artifact only after typed export",
            evidence_outputs: &["support.bundle status", "support.bundle export"],
            local_only: true,
            external_dependency_status: "none; local support evidence only",
            source: "OperatorProjection.support_bundle",
            authority_path: "agentd support_bundle redacted projection",
            launch_preview: "palette.preview support.bundle export",
        },
        WorkflowSpec {
            id: "aom.activation.preview",
            title: "AOM Activation Preview",
            category: "ecosystem",
            capability_id: "aom.activation.preview",
            risk: "activation-gated",
            input_schema: "coordinate; local_registry_snapshot; staging_root; replay_evidence_hash; compatibility_evidence_hash",
            approval_requirements: &[
                "local replay evidence",
                "compatibility evidence",
                "exact approval token",
                "rollback handle",
                "audit journal seal",
            ],
            rollback_expectation: "active artifact set mutation requires rollback handle; preview mutates nothing",
            evidence_outputs: &[
                ".workflow/artifacts/aom/ecosystem-lock.json",
                ".workflow/artifacts/aom/active-set.json",
                ".workflow/artifacts/ecosystem-replay/result.json",
            ],
            local_only: true,
            external_dependency_status: "remote registry optional; baseline uses pinned local registry snapshot",
            source: "OperatorProjection.ecosystem + LocalRegistrySnapshot",
            authority_path: "agent_core::ecosystem activation planning",
            launch_preview: "palette.preview aom.activate.preview agentos:workflow-pack/agentos/service-recovery@1.0.0",
        },
    ]
}
