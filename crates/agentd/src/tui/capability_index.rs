use std::path::PathBuf;

use crate::agent_core::ecosystem::LocalRegistrySnapshot;
use crate::aom::DEFAULT_LOCAL_REGISTRY_PATH;
use crate::api::escape_json;
use crate::audit::redact_summary;
use crate::operator_projection::OperatorProjection;

use super::snapshot::ProjectionSnapshot;

pub const CAPABILITY_INDEX_SCHEMA_VERSION: &str = "agentos.tui-capability-index.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityIndexProjection {
    pub schema_version: &'static str,
    pub read_only: bool,
    pub projection_controller_only: bool,
    pub direct_execution_allowed: bool,
    pub planner_logic: bool,
    pub resolver_logic: bool,
    pub resolver_owner: &'static str,
    pub artifact_count: usize,
    pub capabilities: Vec<CapabilityIndexItem>,
}

impl CapabilityIndexProjection {
    pub fn collect(operator: &OperatorProjection, snapshot: &ProjectionSnapshot) -> Self {
        let registry =
            LocalRegistrySnapshot::from_file(resolve_repo_path(DEFAULT_LOCAL_REGISTRY_PATH)).ok();
        let mut capabilities = built_in_capabilities(operator, snapshot, registry.as_ref());
        capabilities.extend(aom_artifact_capabilities(registry.as_ref()));
        capabilities.sort_by(|left, right| left.id.cmp(&right.id));
        Self {
            schema_version: CAPABILITY_INDEX_SCHEMA_VERSION,
            read_only: true,
            projection_controller_only: true,
            direct_execution_allowed: false,
            planner_logic: false,
            resolver_logic: false,
            resolver_owner: "agent_core::ecosystem",
            artifact_count: registry
                .as_ref()
                .map_or(0, |snapshot| snapshot.artifacts.len()),
            capabilities,
        }
    }

    pub fn render(&self) -> String {
        let mut lines = vec![
            "TUI Capability Catalog".to_string(),
            format!(
                "capability_index schema={} read_only={} projection_controller_only={} direct_execution_allowed={} planner_logic={} resolver_logic={} resolver_owner={} capability_count={} artifact_count={}",
                self.schema_version,
                self.read_only,
                self.projection_controller_only,
                self.direct_execution_allowed,
                self.planner_logic,
                self.resolver_logic,
                self.resolver_owner,
                self.capabilities.len(),
                self.artifact_count
            ),
        ];
        lines.extend(
            self.capabilities
                .iter()
                .enumerate()
                .map(|(index, item)| item.to_cli_line(index)),
        );
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityIndexItem {
    pub id: String,
    pub title: &'static str,
    pub category: &'static str,
    pub status: CapabilityStatus,
    pub source: String,
    pub authority_path: &'static str,
    pub launch_kind: CapabilityLaunchKind,
    pub launch_path: String,
    pub required_approvals: Vec<String>,
    pub unavailable_reason: String,
    pub direct_execute: bool,
}

impl CapabilityIndexItem {
    fn to_cli_line(&self, index: usize) -> String {
        format!(
            "capability[{index}] id={} title=\"{}\" category={} status={} source=\"{}\" authority_path=\"{}\" launch_kind={} launch_path=\"{}\" required_approvals=\"{}\" unavailable_reason=\"{}\" direct_execute={} preview_only={}",
            escape_json(&self.id),
            escape_json(self.title),
            self.category,
            self.status.as_str(),
            escape_json(&redact_summary(&self.source)),
            escape_json(self.authority_path),
            self.launch_kind.as_str(),
            escape_json(&redact_summary(&self.launch_path)),
            escape_json(&self.required_approvals.join("|")),
            escape_json(&redact_summary(&self.unavailable_reason)),
            self.direct_execute,
            !self.direct_execute
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityStatus {
    Available,
    Degraded,
    Unavailable,
}

impl CapabilityStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityLaunchKind {
    Intent,
    Preview,
}

impl CapabilityLaunchKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Preview => "preview",
        }
    }
}

fn built_in_capabilities(
    operator: &OperatorProjection,
    snapshot: &ProjectionSnapshot,
    registry: Option<&LocalRegistrySnapshot>,
) -> Vec<CapabilityIndexItem> {
    vec![
        CapabilityIndexItem {
            id: "service.recovery".to_string(),
            title: "Service Recovery",
            category: "workflow",
            status: if operator.runtime.state == "running" {
                CapabilityStatus::Available
            } else {
                CapabilityStatus::Degraded
            },
            source: "builtin:agent_core::service_recovery".to_string(),
            authority_path: "AgentCore PlanRun + SecurityExecutionEngine",
            launch_kind: CapabilityLaunchKind::Intent,
            launch_path: "intent.submit recover nginx service".to_string(),
            required_approvals: vec!["exact approval token for svc.restart".to_string()],
            unavailable_reason: if operator.runtime.state == "running" {
                "-".to_string()
            } else {
                format!("runtime state is {}", operator.runtime.state)
            },
            direct_execute: false,
        },
        CapabilityIndexItem {
            id: "package.install".to_string(),
            title: "Package Install",
            category: "workflow",
            status: availability_status(operator.adapters.package_manager_status),
            source: "OperatorProjection.adapters.package_manager".to_string(),
            authority_path: "AgentCore package workflow + SecurityExecutionEngine package adapter",
            launch_kind: CapabilityLaunchKind::Intent,
            launch_path: "intent.submit install package through isolated validation".to_string(),
            required_approvals: vec![
                "isolated validation".to_string(),
                "rollback_id".to_string(),
                "exact approval token for pkg.host.install".to_string(),
            ],
            unavailable_reason: unavailable_reason(
                operator.adapters.package_manager_status,
                "package manager semantic tools unavailable",
            ),
            direct_execute: false,
        },
        CapabilityIndexItem {
            id: "content.inspect".to_string(),
            title: "Untrusted Content Inspection",
            category: "workflow",
            status: availability_status(operator.adapters.untrusted_content_status),
            source: "OperatorProjection.adapters.untrusted_content".to_string(),
            authority_path: "AgentCore untrusted content workflow + source-to-sink policy",
            launch_kind: CapabilityLaunchKind::Intent,
            launch_path: "intent.submit inspect pinned untrusted content".to_string(),
            required_approvals: vec![
                "source digest".to_string(),
                "max byte limit".to_string(),
                "source-to-sink policy check".to_string(),
            ],
            unavailable_reason: unavailable_reason(
                operator.adapters.untrusted_content_status,
                "untrusted content semantic tools unavailable",
            ),
            direct_execute: false,
        },
        CapabilityIndexItem {
            id: "rootfs.update".to_string(),
            title: "A/B Rootfs Update",
            category: "production",
            status: if operator.update.assert_ready_for_runbook() {
                CapabilityStatus::Available
            } else if operator.update.status == "failed-closed" {
                CapabilityStatus::Unavailable
            } else {
                CapabilityStatus::Degraded
            },
            source: "OperatorProjection.update".to_string(),
            authority_path: "AgentCore rootfs_update + SecurityExecutionEngine update gate",
            launch_kind: CapabilityLaunchKind::Intent,
            launch_path: "intent.submit stage signed rootfs update for inactive slot".to_string(),
            required_approvals: vec![
                "signed update metadata".to_string(),
                "inactive slot validation".to_string(),
                "rollback evidence".to_string(),
                "exact approval token for activation".to_string(),
            ],
            unavailable_reason: if operator.update.assert_ready_for_runbook() {
                "-".to_string()
            } else {
                format!(
                    "update projection status={} strategy={} active_slot={} inactive_slot={}",
                    operator.update.status,
                    operator.update.slot_strategy,
                    operator.update.active_slot,
                    operator.update.inactive_slot
                )
            },
            direct_execute: false,
        },
        CapabilityIndexItem {
            id: "support.bundle".to_string(),
            title: "Support Bundle Export",
            category: "support",
            status: if operator.support_bundle.redaction_status == "secret-values-redacted"
                && !operator.support_bundle.ecosystem_private_key_paths_included
            {
                CapabilityStatus::Available
            } else {
                CapabilityStatus::Unavailable
            },
            source: "OperatorProjection.support_bundle".to_string(),
            authority_path: "agentd support_bundle redacted projection",
            launch_kind: CapabilityLaunchKind::Preview,
            launch_path: "palette.preview support.bundle export".to_string(),
            required_approvals: vec![
                "redacted audit projection".to_string(),
                "support bundle manifest".to_string(),
            ],
            unavailable_reason: if operator.support_bundle.redaction_status
                == "secret-values-redacted"
            {
                "-".to_string()
            } else {
                format!(
                    "support bundle redaction status={}",
                    operator.support_bundle.redaction_status
                )
            },
            direct_execute: false,
        },
        CapabilityIndexItem {
            id: "aom.activation.preview".to_string(),
            title: "AOM Activation Preview",
            category: "ecosystem",
            status: aom_status(operator, registry),
            source: "OperatorProjection.ecosystem + LocalRegistrySnapshot".to_string(),
            authority_path: "agent_core::ecosystem activation planning",
            launch_kind: CapabilityLaunchKind::Preview,
            launch_path: aom_activation_launch_path(registry),
            required_approvals: vec![
                "local replay evidence".to_string(),
                "compatibility evidence".to_string(),
                "exact approval token".to_string(),
                "rollback handle".to_string(),
                "audit journal seal".to_string(),
            ],
            unavailable_reason: aom_unavailable_reason(operator, registry),
            direct_execute: false,
        },
        CapabilityIndexItem {
            id: "catalog.support.context".to_string(),
            title: "Current Support Context",
            category: "support",
            status: if snapshot.support.degraded {
                CapabilityStatus::Degraded
            } else {
                CapabilityStatus::Available
            },
            source: "ProjectionSnapshot.support".to_string(),
            authority_path: "ProjectionSnapshot + support_bundle projection",
            launch_kind: CapabilityLaunchKind::Preview,
            launch_path: "palette.preview support.bundle status".to_string(),
            required_approvals: vec!["redacted projection input".to_string()],
            unavailable_reason: if snapshot.support.degraded {
                snapshot.support.detail.clone()
            } else {
                "-".to_string()
            },
            direct_execute: false,
        },
    ]
}

fn aom_artifact_capabilities(registry: Option<&LocalRegistrySnapshot>) -> Vec<CapabilityIndexItem> {
    let Some(registry) = registry else {
        return Vec::new();
    };
    registry
        .artifacts
        .iter()
        .map(|artifact| {
            let coordinate = artifact.coordinate.as_string();
            CapabilityIndexItem {
                id: format!("aom.artifact.{coordinate}"),
                title: "AOM Artifact",
                category: artifact.coordinate.kind.as_str(),
                status: if artifact.revoked {
                    CapabilityStatus::Unavailable
                } else {
                    CapabilityStatus::Available
                },
                source: format!(
                    "LocalRegistrySnapshot coordinate={} trust_tier={}",
                    coordinate,
                    artifact.trust_tier.as_str()
                ),
                authority_path: "agent_core::ecosystem registry projection",
                launch_kind: CapabilityLaunchKind::Preview,
                launch_path: format!("aom.explain {coordinate}"),
                required_approvals: vec![
                    "activation requires AgentCore PlanSpec".to_string(),
                    "activation requires SecurityExecutionEngine".to_string(),
                    "activation requires exact approval".to_string(),
                ],
                unavailable_reason: if artifact.revoked {
                    format!(
                        "artifact revoked advisories={}",
                        artifact.advisory_refs.join("|")
                    )
                } else {
                    "-".to_string()
                },
                direct_execute: false,
            }
        })
        .collect()
}

fn availability_status(status: &str) -> CapabilityStatus {
    if status == "available" {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::Unavailable
    }
}

fn unavailable_reason(status: &str, reason: &str) -> String {
    if status == "available" {
        "-".to_string()
    } else {
        format!("{reason}: status={status}")
    }
}

fn aom_status(
    operator: &OperatorProjection,
    registry: Option<&LocalRegistrySnapshot>,
) -> CapabilityStatus {
    if registry.is_none() || operator.ecosystem.local_registry_status == "missing" {
        CapabilityStatus::Unavailable
    } else if operator.ecosystem.network_required {
        CapabilityStatus::Degraded
    } else {
        CapabilityStatus::Available
    }
}

fn aom_activation_launch_path(registry: Option<&LocalRegistrySnapshot>) -> String {
    registry
        .and_then(|snapshot| {
            snapshot
                .artifacts
                .iter()
                .find(|artifact| {
                    artifact.coordinate.kind.as_str() == "workflow-pack" && !artifact.revoked
                })
                .map(|artifact| artifact.coordinate.as_string())
        })
        .map(|coordinate| format!("aom.activate.preview {coordinate}"))
        .unwrap_or_else(|| "aom.search".to_string())
}

fn aom_unavailable_reason(
    operator: &OperatorProjection,
    registry: Option<&LocalRegistrySnapshot>,
) -> String {
    if registry.is_none() {
        "local registry snapshot is unreadable".to_string()
    } else if operator.ecosystem.network_required {
        "local registry projection requires network; baseline remains local-only".to_string()
    } else {
        "-".to_string()
    }
}

fn resolve_repo_path(path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.exists() {
        return candidate;
    }
    let mut current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        let joined = current.join(path);
        if joined.exists() {
            return joined;
        }
        if !current.pop() {
            return candidate;
        }
    }
}
