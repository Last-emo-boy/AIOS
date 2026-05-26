use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::agent_core::ecosystem::LocalRegistrySnapshot;
use crate::aom::{DEFAULT_LOCAL_REGISTRY_PATH, DEFAULT_STAGING_ROOT};
use crate::api::{RiskClass, escape_json};
use crate::audit::{AuditJournal, RuntimeAuditProjection, redact_summary};
use crate::lifecycle::{Agentd, HealthReport, LifecycleState};
use crate::runtime_contracts::stable_contract_hash;
use crate::safety::SafetyGateConfig;
use crate::support_bundle::{EcosystemSupportBundleProjection, SupportBundleProjection};
use crate::tools::TOOL_SCHEMAS;

pub const OPERATOR_PROJECTION_SCHEMA_VERSION: &str = "agentd-operator-projection/v1";
pub const DEFAULT_ECOSYSTEM_LOCKFILE_PATH: &str = ".workflow/artifacts/aom/ecosystem-lock.json";
pub const DEFAULT_ACTIVE_ARTIFACT_SET_PATH: &str = ".workflow/artifacts/aom/active-set.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorProjection {
    pub schema_version: &'static str,
    pub source: &'static str,
    pub read_only: bool,
    pub redaction: &'static str,
    pub runtime: OperatorRuntimeProjection,
    pub telemetry: OperatorTelemetryProjection,
    pub audit: OperatorAuditProjection,
    pub update: OperatorUpdateProjection,
    pub adapters: OperatorAdapterProjection,
    pub ecosystem: OperatorEcosystemProjection,
    pub support_bundle: OperatorSupportBundleProjection,
    pub safety: OperatorSafetyProjection,
}

impl OperatorProjection {
    pub fn collect(
        agentd: &Agentd,
        audit_journal: Option<&AuditJournal>,
        run_id: Option<&str>,
    ) -> io::Result<Self> {
        let health = agentd.health_report();
        let audit = OperatorAuditProjection::from_journal(audit_journal, run_id)?;
        let telemetry = OperatorTelemetryProjection::from_audit(&audit);
        let update = OperatorUpdateProjection::from_journal(audit_journal)?;
        Ok(Self {
            schema_version: OPERATOR_PROJECTION_SCHEMA_VERSION,
            source: "agentd-read-only",
            read_only: true,
            redaction: "secret-values-redacted",
            runtime: OperatorRuntimeProjection::from_health(&health),
            telemetry,
            audit,
            update,
            adapters: OperatorAdapterProjection::from_tool_manifest(),
            ecosystem: OperatorEcosystemProjection::from_defaults(),
            support_bundle: OperatorSupportBundleProjection::from_journal(audit_journal)?,
            safety: OperatorSafetyProjection::from_gate(&SafetyGateConfig::default_gate()),
        })
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":\"{}\",\"source\":\"{}\",\"read_only\":{},\"redaction\":\"{}\",\"runtime\":{},\"telemetry\":{},\"audit\":{},\"update\":{},\"adapters\":{},\"ecosystem\":{},\"support_bundle\":{},\"safety\":{}}}",
            self.schema_version,
            self.source,
            self.read_only,
            self.redaction,
            self.runtime.to_json(),
            self.telemetry.to_json(),
            self.audit.to_json(),
            self.update.to_json(),
            self.adapters.to_json(),
            self.ecosystem.to_json(),
            self.support_bundle.to_json(),
            self.safety.to_json()
        )
    }

    pub fn to_cli_lines(&self) -> Vec<String> {
        vec![
            format!(
                "schema={} source={} read_only={} redaction={}",
                self.schema_version, self.source, self.read_only, self.redaction
            ),
            self.runtime.to_cli_line(),
            self.telemetry.to_cli_line(),
            self.audit.to_cli_line(),
            self.update.to_cli_line(),
            self.adapters.to_cli_line(),
            self.ecosystem.to_cli_line(),
            self.support_bundle.to_cli_line(),
            self.safety.to_cli_line(),
        ]
    }

    pub fn to_cli_text(&self) -> String {
        self.to_cli_lines().join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorEcosystemProjection {
    pub schema_version: &'static str,
    pub local_registry_path: String,
    pub local_registry_status: &'static str,
    pub registry_snapshot_digest: Option<String>,
    pub registry_artifact_count: usize,
    pub core_artifact_count: usize,
    pub core_artifacts: Vec<String>,
    pub staging_root: String,
    pub staged_artifact_count: usize,
    pub active_set_path: String,
    pub active_set_status: &'static str,
    pub active_artifact_count: usize,
    pub pending_activation_count: usize,
    pub lockfile_path: String,
    pub lockfile_hash: Option<String>,
    pub durable_state_paths: Vec<String>,
    pub lifecycle_commands: Vec<String>,
    pub activation_status: &'static str,
    pub activation_authority: &'static str,
    pub blocked_until: Vec<String>,
    pub required_approvals: Vec<String>,
    pub blocked_reasons: Vec<String>,
    pub staged_artifacts_active: bool,
    pub staged_and_active_separated: bool,
    pub normal_shell_available: bool,
    pub agentd_resolver_logic: bool,
    pub resolver_owner: &'static str,
    pub network_required: bool,
}

impl OperatorEcosystemProjection {
    fn from_defaults() -> Self {
        let registry_path = resolve_projection_path(DEFAULT_LOCAL_REGISTRY_PATH);
        let staging_root = resolve_projection_path(DEFAULT_STAGING_ROOT);
        let active_set_path = resolve_projection_path(DEFAULT_ACTIVE_ARTIFACT_SET_PATH);
        let lockfile_path = resolve_projection_path(DEFAULT_ECOSYSTEM_LOCKFILE_PATH);
        let registry = RegistryProjection::from_file(&registry_path);
        let staged_artifact_count = count_named_files(&staging_root, "staging-report.json");
        let active_set = ActiveSetProjection::from_file(&active_set_path);
        let lockfile_hash = file_stable_hash(&lockfile_path);
        Self {
            schema_version: "agentos.operator-ecosystem-projection.v1",
            local_registry_path: DEFAULT_LOCAL_REGISTRY_PATH.to_string(),
            local_registry_status: registry.status,
            registry_snapshot_digest: registry.snapshot_digest,
            registry_artifact_count: registry.artifact_count,
            core_artifact_count: registry.core_artifacts.len(),
            core_artifacts: registry.core_artifacts,
            staging_root: DEFAULT_STAGING_ROOT.to_string(),
            staged_artifact_count,
            active_set_path: DEFAULT_ACTIVE_ARTIFACT_SET_PATH.to_string(),
            active_set_status: active_set.status,
            active_artifact_count: active_set.artifact_count,
            pending_activation_count: staged_artifact_count,
            lockfile_path: DEFAULT_ECOSYSTEM_LOCKFILE_PATH.to_string(),
            lockfile_hash,
            durable_state_paths: [
                DEFAULT_LOCAL_REGISTRY_PATH,
                DEFAULT_STAGING_ROOT,
                DEFAULT_ECOSYSTEM_LOCKFILE_PATH,
                DEFAULT_ACTIVE_ARTIFACT_SET_PATH,
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
            lifecycle_commands: [
                "aom.search",
                "aom.show",
                "aom.verify",
                "aom.stage",
                "aom.explain",
                "aom.activate",
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
            activation_status: "gated",
            activation_authority: "AgentCore PlanSpec + SecurityExecutionEngine",
            blocked_until: [
                "local replay evidence",
                "compatibility evidence",
                "exact approval token",
                "rollback handle",
                "audit journal seal",
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
            required_approvals: [
                "exact approval token for ecosystem.activate",
                "policy broadening approval when activation broadens policy",
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
            blocked_reasons: [
                "install and stage are inert until activation PlanSpec is approved",
                "activation must provide replay and compatibility evidence",
                "active artifact set mutation requires rollback metadata",
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
            staged_artifacts_active: false,
            staged_and_active_separated: true,
            normal_shell_available: false,
            agentd_resolver_logic: false,
            resolver_owner: "agent_core::ecosystem",
            network_required: registry.network_required,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":\"{}\",\"local_registry_path\":\"{}\",\"local_registry_status\":\"{}\",\"registry_snapshot_digest\":{},\"registry_artifact_count\":{},\"core_artifact_count\":{},\"core_artifacts\":{},\"staging_root\":\"{}\",\"staged_artifact_count\":{},\"active_set_path\":\"{}\",\"active_set_status\":\"{}\",\"active_artifact_count\":{},\"pending_activation_count\":{},\"lockfile_path\":\"{}\",\"lockfile_hash\":{},\"durable_state_paths\":{},\"lifecycle_commands\":{},\"activation_status\":\"{}\",\"activation_authority\":\"{}\",\"blocked_until\":{},\"required_approvals\":{},\"blocked_reasons\":{},\"staged_artifacts_active\":{},\"staged_and_active_separated\":{},\"normal_shell_available\":{},\"agentd_resolver_logic\":{},\"resolver_owner\":\"{}\",\"network_required\":{}}}",
            self.schema_version,
            escape_json(&self.local_registry_path),
            self.local_registry_status,
            optional_json(self.registry_snapshot_digest.as_deref()),
            self.registry_artifact_count,
            self.core_artifact_count,
            string_array_json(&self.core_artifacts),
            escape_json(&self.staging_root),
            self.staged_artifact_count,
            escape_json(&self.active_set_path),
            self.active_set_status,
            self.active_artifact_count,
            self.pending_activation_count,
            escape_json(&self.lockfile_path),
            optional_json(self.lockfile_hash.as_deref()),
            string_array_json(&self.durable_state_paths),
            string_array_json(&self.lifecycle_commands),
            self.activation_status,
            escape_json(self.activation_authority),
            string_array_json(&self.blocked_until),
            string_array_json(&self.required_approvals),
            string_array_json(&self.blocked_reasons),
            self.staged_artifacts_active,
            self.staged_and_active_separated,
            self.normal_shell_available,
            self.agentd_resolver_logic,
            self.resolver_owner,
            self.network_required
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "ecosystem registry={} registry_status={} snapshot_digest={} artifacts={} core_artifacts={} staging_root={} staged_artifacts={} active_set={} active_set_status={} active_artifacts={} pending_activation={} lockfile={} lockfile_hash={} commands={} activation_status={} activation_authority=\"{}\" staged_artifacts_active={} staged_active_separated={} normal_shell_available={} agentd_resolver_logic={} resolver_owner={} network_required={} required_approvals={} blocked_until={} blocked_reasons={}",
            self.local_registry_path,
            self.local_registry_status,
            self.registry_snapshot_digest.as_deref().unwrap_or("-"),
            self.registry_artifact_count,
            self.core_artifacts.join("|"),
            self.staging_root,
            self.staged_artifact_count,
            self.active_set_path,
            self.active_set_status,
            self.active_artifact_count,
            self.pending_activation_count,
            self.lockfile_path,
            self.lockfile_hash.as_deref().unwrap_or("-"),
            self.lifecycle_commands.join("|"),
            self.activation_status,
            self.activation_authority,
            self.staged_artifacts_active,
            self.staged_and_active_separated,
            self.normal_shell_available,
            self.agentd_resolver_logic,
            self.resolver_owner,
            self.network_required,
            self.required_approvals.join("|"),
            self.blocked_until.join("|"),
            self.blocked_reasons.join("|")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryProjection {
    status: &'static str,
    snapshot_digest: Option<String>,
    artifact_count: usize,
    core_artifacts: Vec<String>,
    network_required: bool,
}

impl RegistryProjection {
    fn from_file(path: &Path) -> Self {
        if !path.is_file() {
            return Self {
                status: "missing",
                snapshot_digest: None,
                artifact_count: 0,
                core_artifacts: Vec::new(),
                network_required: false,
            };
        }

        let Ok(snapshot) = LocalRegistrySnapshot::from_file(path) else {
            return Self {
                status: "invalid",
                snapshot_digest: None,
                artifact_count: 0,
                core_artifacts: Vec::new(),
                network_required: false,
            };
        };

        let mut core_artifacts = snapshot
            .artifacts
            .iter()
            .filter(|artifact| artifact.trust_tier.as_str() == "core")
            .map(|artifact| artifact.coordinate.as_string())
            .collect::<Vec<_>>();
        core_artifacts.sort();
        let network_required = snapshot
            .artifacts
            .iter()
            .any(|artifact| is_network_uri(&artifact.source_uri));

        Self {
            status: "configured",
            snapshot_digest: Some(snapshot.snapshot_digest),
            artifact_count: snapshot.artifacts.len(),
            core_artifacts,
            network_required,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSetProjection {
    status: &'static str,
    artifact_count: usize,
}

impl ActiveSetProjection {
    fn from_file(path: &Path) -> Self {
        if !path.is_file() {
            return Self {
                status: "missing",
                artifact_count: 0,
            };
        }
        let Ok(content) = fs::read_to_string(path) else {
            return Self {
                status: "invalid",
                artifact_count: 0,
            };
        };
        Self {
            status: "present",
            artifact_count: json_key_count(&content, "coordinate"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSupportBundleProjection {
    pub status: String,
    pub bundle_id: Option<String>,
    pub redaction_status: String,
    pub audit_excerpt_count: usize,
    pub deterministic: bool,
    pub ecosystem_registry_snapshot_hash: Option<String>,
    pub ecosystem_active_set_hash: Option<String>,
    pub ecosystem_trust_tiers: Vec<String>,
    pub ecosystem_revocation_status: String,
    pub ecosystem_private_key_paths_included: bool,
}

impl OperatorSupportBundleProjection {
    fn from_journal(audit_journal: Option<&AuditJournal>) -> io::Result<Self> {
        let ecosystem = EcosystemSupportBundleProjection::from_defaults();
        let Some(journal) = audit_journal else {
            return Ok(Self::from_ecosystem(
                "not-configured",
                None,
                "secret-values-redacted",
                0,
                true,
                ecosystem,
            ));
        };
        let latest_run = journal.latest_run()?;
        let Some(run_id) = latest_run else {
            return Ok(Self::from_ecosystem(
                "no-run",
                None,
                "secret-values-redacted",
                0,
                true,
                ecosystem,
            ));
        };
        let projection = SupportBundleProjection::from_journal(
            journal,
            format!("support-{run_id}"),
            vec![run_id.clone()],
        )?;
        Ok(Self::from_ecosystem(
            "ready",
            Some(projection.manifest.bundle_id.clone()),
            &projection.manifest.redaction_status,
            projection.audit_excerpt_count,
            projection.deterministic,
            projection.ecosystem,
        ))
    }

    fn from_ecosystem(
        status: &str,
        bundle_id: Option<String>,
        redaction_status: &str,
        audit_excerpt_count: usize,
        deterministic: bool,
        ecosystem: EcosystemSupportBundleProjection,
    ) -> Self {
        Self {
            status: status.to_string(),
            bundle_id,
            redaction_status: redaction_status.to_string(),
            audit_excerpt_count,
            deterministic,
            ecosystem_registry_snapshot_hash: ecosystem.registry_snapshot_hash,
            ecosystem_active_set_hash: ecosystem.active_set_hash,
            ecosystem_trust_tiers: ecosystem.trust_tiers,
            ecosystem_revocation_status: ecosystem.revocation_status.to_string(),
            ecosystem_private_key_paths_included: ecosystem.private_key_paths_included,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"status\":\"{}\",\"bundle_id\":{},\"redaction_status\":\"{}\",\"audit_excerpt_count\":{},\"deterministic\":{},\"ecosystem_registry_snapshot_hash\":{},\"ecosystem_active_set_hash\":{},\"ecosystem_trust_tiers\":{},\"ecosystem_revocation_status\":\"{}\",\"ecosystem_private_key_paths_included\":{}}}",
            escape_json(&self.status),
            optional_json(self.bundle_id.as_deref()),
            escape_json(&self.redaction_status),
            self.audit_excerpt_count,
            self.deterministic,
            optional_json(self.ecosystem_registry_snapshot_hash.as_deref()),
            optional_json(self.ecosystem_active_set_hash.as_deref()),
            string_array_json(&self.ecosystem_trust_tiers),
            escape_json(&self.ecosystem_revocation_status),
            self.ecosystem_private_key_paths_included
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "support_bundle status={} bundle={} redaction={} audit_excerpt_count={} deterministic={} ecosystem_registry_hash={} ecosystem_active_hash={} ecosystem_trust_tiers={} ecosystem_revocation={} private_key_paths_included={}",
            self.status,
            self.bundle_id.as_deref().unwrap_or("-"),
            self.redaction_status,
            self.audit_excerpt_count,
            self.deterministic,
            self.ecosystem_registry_snapshot_hash
                .as_deref()
                .unwrap_or("-"),
            self.ecosystem_active_set_hash.as_deref().unwrap_or("-"),
            self.ecosystem_trust_tiers.join("|"),
            self.ecosystem_revocation_status,
            self.ecosystem_private_key_paths_included
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorRuntimeProjection {
    pub state: String,
    pub run_mode: &'static str,
    pub planner_mode: &'static str,
    pub arbitrary_shell_enabled: bool,
    pub module_count: usize,
    pub last_error: Option<String>,
}

impl OperatorRuntimeProjection {
    fn from_health(health: &HealthReport) -> Self {
        Self {
            state: lifecycle_state(&health.state).to_string(),
            run_mode: health.run_mode,
            planner_mode: health.planner_mode,
            arbitrary_shell_enabled: health.arbitrary_shell_enabled,
            module_count: health.module_count,
            last_error: health
                .last_error
                .as_ref()
                .map(|error| redact_summary(error)),
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"state\":\"{}\",\"run_mode\":\"{}\",\"planner_mode\":\"{}\",\"arbitrary_shell_enabled\":{},\"module_count\":{},\"last_error\":{}}}",
            escape_json(&self.state),
            self.run_mode,
            self.planner_mode,
            self.arbitrary_shell_enabled,
            self.module_count,
            optional_json(self.last_error.as_deref())
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "runtime state={} run_mode={} planner_mode={} arbitrary_shell_enabled={} modules={} last_error={}",
            self.state,
            self.run_mode,
            self.planner_mode,
            self.arbitrary_shell_enabled,
            self.module_count,
            self.last_error.as_deref().unwrap_or("-")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorTelemetryProjection {
    pub latest_run_id: Option<String>,
    pub latest_run_status: String,
    pub event_count: usize,
    pub warning_count: usize,
    pub unresolved_effects: usize,
}

impl OperatorTelemetryProjection {
    fn from_audit(audit: &OperatorAuditProjection) -> Self {
        Self {
            latest_run_id: audit.latest_run_id.clone(),
            latest_run_status: audit.latest_run_status.clone(),
            event_count: audit.event_count,
            warning_count: audit.warning_count,
            unresolved_effects: audit.unresolved_effects,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"latest_run_id\":{},\"latest_run_status\":\"{}\",\"event_count\":{},\"warning_count\":{},\"unresolved_effects\":{}}}",
            optional_json(self.latest_run_id.as_deref()),
            escape_json(&self.latest_run_status),
            self.event_count,
            self.warning_count,
            self.unresolved_effects
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "telemetry latest_run={} status={} events={} warnings={} unresolved_effects={}",
            self.latest_run_id.as_deref().unwrap_or("-"),
            self.latest_run_status,
            self.event_count,
            self.warning_count,
            self.unresolved_effects
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorAuditProjection {
    pub journal_path: Option<String>,
    pub requested_run_id: Option<String>,
    pub latest_run_id: Option<String>,
    pub latest_step_id: Option<String>,
    pub latest_run_status: String,
    pub audit_seal_status: String,
    pub event_count: usize,
    pub effect_prepared_count: usize,
    pub commit_sealed_count: usize,
    pub rollback_pending_count: usize,
    pub unresolved_effects: usize,
    pub warning_count: usize,
    pub warnings: Vec<String>,
    pub remote_mirror_status: String,
    pub remote_mirror_failure_policy: Option<String>,
    pub remote_mirror_non_local_side_effects_allowed: bool,
}

impl OperatorAuditProjection {
    fn from_journal(
        audit_journal: Option<&AuditJournal>,
        run_id: Option<&str>,
    ) -> io::Result<Self> {
        let Some(journal) = audit_journal else {
            return Ok(Self::empty(None, run_id));
        };

        let requested_run_id = run_id.map(ToString::to_string);
        let projection = match run_id {
            Some("latest") | None => journal.project_latest_runtime_run()?,
            Some(run_id) => journal.project_runtime_run(run_id)?,
        };
        let unresolved_effects = journal.unresolved_effects()?.len();
        let remote_mirror = RemoteMirrorProjection::from_lines(&journal.event_lines()?);
        let journal_path = Some(journal.path().display().to_string());

        let Some(projection) = projection else {
            let mut empty = Self {
                journal_path,
                requested_run_id,
                ..Self::empty(None, None)
            };
            empty.remote_mirror_status = remote_mirror.status;
            empty.remote_mirror_failure_policy = remote_mirror.failure_policy;
            empty.remote_mirror_non_local_side_effects_allowed =
                remote_mirror.non_local_side_effects_allowed;
            return Ok(empty);
        };

        let mut audit = Self::from_runtime_projection(
            journal_path,
            requested_run_id,
            &projection,
            unresolved_effects,
        );
        audit.remote_mirror_status = remote_mirror.status;
        audit.remote_mirror_failure_policy = remote_mirror.failure_policy;
        audit.remote_mirror_non_local_side_effects_allowed =
            remote_mirror.non_local_side_effects_allowed;
        Ok(audit)
    }

    fn empty(journal_path: Option<String>, run_id: Option<&str>) -> Self {
        Self {
            journal_path,
            requested_run_id: run_id.map(ToString::to_string),
            latest_run_id: None,
            latest_step_id: None,
            latest_run_status: "no-run".to_string(),
            audit_seal_status: "unknown".to_string(),
            event_count: 0,
            effect_prepared_count: 0,
            commit_sealed_count: 0,
            rollback_pending_count: 0,
            unresolved_effects: 0,
            warning_count: 0,
            warnings: Vec::new(),
            remote_mirror_status: "not-observed".to_string(),
            remote_mirror_failure_policy: None,
            remote_mirror_non_local_side_effects_allowed: true,
        }
    }

    fn from_runtime_projection(
        journal_path: Option<String>,
        requested_run_id: Option<String>,
        projection: &RuntimeAuditProjection,
        unresolved_effects: usize,
    ) -> Self {
        let latest_step = projection.steps.last();
        let effect_prepared_count = projection
            .steps
            .iter()
            .filter(|step| step.effect_prepared)
            .count();
        let commit_sealed_count = projection
            .steps
            .iter()
            .filter(|step| step.commit_sealed)
            .count();
        let rollback_pending_count = projection
            .steps
            .iter()
            .filter(|step| step.effect_state == "rollback-pending")
            .count();
        let audit_seal_status = audit_seal_status(
            effect_prepared_count,
            commit_sealed_count,
            rollback_pending_count,
            unresolved_effects,
        )
        .to_string();

        Self {
            journal_path,
            requested_run_id,
            latest_run_id: Some(projection.run_id.clone()),
            latest_step_id: latest_step.map(|step| step.step_id.clone()),
            latest_run_status: latest_step
                .map(|step| step.status.clone())
                .unwrap_or_else(|| "no-step".to_string()),
            audit_seal_status,
            event_count: projection.event_count(),
            effect_prepared_count,
            commit_sealed_count,
            rollback_pending_count,
            unresolved_effects,
            warning_count: projection.warnings.len(),
            warnings: projection
                .warnings
                .iter()
                .map(|warning| redact_summary(warning))
                .collect(),
            remote_mirror_status: "not-observed".to_string(),
            remote_mirror_failure_policy: None,
            remote_mirror_non_local_side_effects_allowed: true,
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"journal_path\":{},\"requested_run_id\":{},\"latest_run_id\":{},\"latest_step_id\":{},\"latest_run_status\":\"{}\",\"audit_seal_status\":\"{}\",\"event_count\":{},\"effect_prepared_count\":{},\"commit_sealed_count\":{},\"rollback_pending_count\":{},\"unresolved_effects\":{},\"warning_count\":{},\"warnings\":{},\"remote_mirror_status\":\"{}\",\"remote_mirror_failure_policy\":{},\"remote_mirror_non_local_side_effects_allowed\":{}}}",
            optional_json(self.journal_path.as_deref()),
            optional_json(self.requested_run_id.as_deref()),
            optional_json(self.latest_run_id.as_deref()),
            optional_json(self.latest_step_id.as_deref()),
            escape_json(&self.latest_run_status),
            escape_json(&self.audit_seal_status),
            self.event_count,
            self.effect_prepared_count,
            self.commit_sealed_count,
            self.rollback_pending_count,
            self.unresolved_effects,
            self.warning_count,
            string_array_json(&self.warnings),
            escape_json(&self.remote_mirror_status),
            optional_json(self.remote_mirror_failure_policy.as_deref()),
            self.remote_mirror_non_local_side_effects_allowed
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "audit journal={} requested_run={} latest_run={} step={} status={} seal={} prepared={} sealed={} rollback_pending={} unresolved_effects={} warnings={} remote_mirror={} remote_policy={} non_local_side_effects_allowed={}",
            self.journal_path.as_deref().unwrap_or("-"),
            self.requested_run_id.as_deref().unwrap_or("-"),
            self.latest_run_id.as_deref().unwrap_or("-"),
            self.latest_step_id.as_deref().unwrap_or("-"),
            self.latest_run_status,
            self.audit_seal_status,
            self.effect_prepared_count,
            self.commit_sealed_count,
            self.rollback_pending_count,
            self.unresolved_effects,
            self.warning_count,
            self.remote_mirror_status,
            self.remote_mirror_failure_policy.as_deref().unwrap_or("-"),
            self.remote_mirror_non_local_side_effects_allowed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorUpdateProjection {
    pub slot_strategy: String,
    pub active_slot: String,
    pub inactive_slot: String,
    pub pending_activation: bool,
    pub rollback_available: bool,
    pub status: String,
}

impl OperatorUpdateProjection {
    fn contract_only() -> Self {
        Self {
            slot_strategy: "ab-rootfs-contract".to_string(),
            active_slot: "unknown".to_string(),
            inactive_slot: "unknown".to_string(),
            pending_activation: false,
            rollback_available: false,
            status: "not-configured".to_string(),
        }
    }

    fn from_journal(audit_journal: Option<&AuditJournal>) -> io::Result<Self> {
        let Some(journal) = audit_journal else {
            return Ok(Self::contract_only());
        };
        let Some(summary) = journal.event_lines()?.iter().rev().find_map(|line| {
            if json_string(line, "step_id").as_deref() == Some("ab-rootfs-update") {
                json_string(line, "summary")
            } else {
                None
            }
        }) else {
            return Ok(Self::contract_only());
        };
        let state = summary_value(&summary, "state").unwrap_or_else(|| "Unknown".to_string());
        let active_slot =
            summary_value(&summary, "active_slot").unwrap_or_else(|| "unknown".to_string());
        let inactive_slot =
            summary_value(&summary, "inactive_slot").unwrap_or_else(|| "unknown".to_string());
        Ok(Self {
            slot_strategy: "ab-rootfs-runtime".to_string(),
            active_slot,
            inactive_slot,
            pending_activation: matches!(
                state.as_str(),
                "InactiveSlotPrepared"
                    | "InactiveSlotValidated"
                    | "ActivationScheduled"
                    | "PendingHealth"
            ),
            rollback_available: !matches!(state.as_str(), "FailedClosed" | "Unknown"),
            status: update_status(&state).to_string(),
        })
    }

    pub fn assert_ready_for_runbook(&self) -> bool {
        self.slot_strategy == "ab-rootfs-runtime"
            && self.active_slot != "unknown"
            && self.inactive_slot != "unknown"
            && self.rollback_available
            && self.status != "failed-closed"
            && self.status != "not-configured"
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"slot_strategy\":\"{}\",\"active_slot\":\"{}\",\"inactive_slot\":\"{}\",\"pending_activation\":{},\"rollback_available\":{},\"status\":\"{}\"}}",
            escape_json(&self.slot_strategy),
            escape_json(&self.active_slot),
            escape_json(&self.inactive_slot),
            self.pending_activation,
            self.rollback_available,
            escape_json(&self.status)
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "update strategy={} active_slot={} inactive_slot={} pending_activation={} rollback_available={} status={}",
            self.slot_strategy,
            self.active_slot,
            self.inactive_slot,
            self.pending_activation,
            self.rollback_available,
            self.status
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteMirrorProjection {
    status: String,
    failure_policy: Option<String>,
    non_local_side_effects_allowed: bool,
}

impl RemoteMirrorProjection {
    fn from_lines(lines: &[String]) -> Self {
        let Some(summary) = lines.iter().rev().find_map(|line| {
            let summary = json_string(line, "summary")?;
            if summary.contains("remote-audit-mirror failure") {
                Some(redact_summary(&summary))
            } else {
                None
            }
        }) else {
            return Self {
                status: "not-observed".to_string(),
                failure_policy: None,
                non_local_side_effects_allowed: true,
            };
        };
        let status = summary_value(&summary, "status").unwrap_or_else(|| "warning".to_string());
        let failure_policy = summary_value(&summary, "policy");
        let non_local_side_effects_allowed = !matches!(status.as_str(), "paused" | "failed-closed");
        Self {
            status,
            failure_policy,
            non_local_side_effects_allowed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorAdapterProjection {
    pub tool_manifest_status: &'static str,
    pub tool_count: usize,
    pub read_only_tools: usize,
    pub write_with_diff_tools: usize,
    pub execute_with_confirmation_tools: usize,
    pub privileged_tools: usize,
    pub package_manager_status: &'static str,
    pub untrusted_content_status: &'static str,
    pub audit_projection_status: &'static str,
}

impl OperatorAdapterProjection {
    fn from_tool_manifest() -> Self {
        Self {
            tool_manifest_status: "available",
            tool_count: TOOL_SCHEMAS.len(),
            read_only_tools: count_tools(RiskClass::ReadOnly),
            write_with_diff_tools: count_tools(RiskClass::WriteWithDiff),
            execute_with_confirmation_tools: count_tools(RiskClass::ExecuteWithConfirmation),
            privileged_tools: count_tools(RiskClass::PrivilegedWithHumanApproval),
            package_manager_status: availability(&[
                "pkg.fetch.metadata",
                "pkg.isolate.install",
                "pkg.host.install",
                "pkg.host.verify",
            ]),
            untrusted_content_status: availability(&[
                "content.fetch",
                "content.sanitize",
                "content.summarize",
                "policy.source_to_sink.check",
            ]),
            audit_projection_status: availability(&["audit.project"]),
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"tool_manifest_status\":\"{}\",\"tool_count\":{},\"read_only_tools\":{},\"write_with_diff_tools\":{},\"execute_with_confirmation_tools\":{},\"privileged_tools\":{},\"package_manager_status\":\"{}\",\"untrusted_content_status\":\"{}\",\"audit_projection_status\":\"{}\"}}",
            self.tool_manifest_status,
            self.tool_count,
            self.read_only_tools,
            self.write_with_diff_tools,
            self.execute_with_confirmation_tools,
            self.privileged_tools,
            self.package_manager_status,
            self.untrusted_content_status,
            self.audit_projection_status
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "adapters tool_manifest={} tools={} read_only={} write_with_diff={} execute_with_confirmation={} privileged={} package_manager={} untrusted_content={} audit_projection={}",
            self.tool_manifest_status,
            self.tool_count,
            self.read_only_tools,
            self.write_with_diff_tools,
            self.execute_with_confirmation_tools,
            self.privileged_tools,
            self.package_manager_status,
            self.untrusted_content_status,
            self.audit_projection_status
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSafetyProjection {
    pub gate_name: &'static str,
    pub command: &'static str,
    pub fail_closed: bool,
    pub required_scenarios: usize,
    pub status: &'static str,
}

impl OperatorSafetyProjection {
    fn from_gate(gate: &SafetyGateConfig) -> Self {
        Self {
            gate_name: gate.name,
            command: gate.command,
            fail_closed: gate.fail_closed,
            required_scenarios: gate.required_scenarios.len(),
            status: if gate.fail_closed {
                "configured-fail-closed"
            } else {
                "configured-open"
            },
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"gate_name\":\"{}\",\"command\":\"{}\",\"fail_closed\":{},\"required_scenarios\":{},\"status\":\"{}\"}}",
            self.gate_name,
            escape_json(self.command),
            self.fail_closed,
            self.required_scenarios,
            self.status
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "safety gate={} fail_closed={} scenarios={} status={}",
            self.gate_name, self.fail_closed, self.required_scenarios, self.status
        )
    }
}

fn lifecycle_state(state: &LifecycleState) -> &'static str {
    match state {
        LifecycleState::Created => "created",
        LifecycleState::Running => "running",
        LifecycleState::Stopping => "stopping",
        LifecycleState::Stopped => "stopped",
    }
}

fn audit_seal_status(
    prepared: usize,
    sealed: usize,
    rollback_pending: usize,
    unresolved: usize,
) -> &'static str {
    if rollback_pending > 0 {
        "rollback-pending"
    } else if unresolved > 0 || prepared > sealed {
        "unsealed"
    } else if sealed > 0 {
        "sealed"
    } else {
        "no-effects"
    }
}

fn count_tools(risk: RiskClass) -> usize {
    TOOL_SCHEMAS
        .iter()
        .filter(|schema| schema.risk == risk)
        .count()
}

fn availability(required_tools: &[&str]) -> &'static str {
    if required_tools
        .iter()
        .all(|name| TOOL_SCHEMAS.iter().any(|schema| schema.name == *name))
    {
        "available"
    } else {
        "missing"
    }
}

fn resolve_projection_path(path: &str) -> PathBuf {
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

fn count_named_files(root: &Path, filename: &str) -> usize {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    let mut count = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            count += count_named_files(&path, filename);
        } else if path.file_name().and_then(|value| value.to_str()) == Some(filename) {
            count += 1;
        }
    }
    count
}

fn file_stable_hash(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|content| stable_contract_hash(&content))
}

fn is_network_uri(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn json_key_count(content: &str, key: &str) -> usize {
    let needle = format!("\"{key}\"");
    content.match_indices(&needle).count()
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

fn json_string(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
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

fn update_status(state: &str) -> &'static str {
    match state {
        "Idle" => "idle",
        "ArtifactVerified" => "artifact-verified",
        "InactiveSlotPrepared" => "inactive-slot-prepared",
        "InactiveSlotValidated" => "inactive-slot-validated",
        "ActivationScheduled" => "activation-scheduled",
        "PendingHealth" => "pending-health",
        "Committed" => "committed",
        "RollbackScheduled" => "rollback-scheduled",
        "RolledBack" => "rolled-back",
        "FailedClosed" => "failed-closed",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use super::*;
    use crate::agent_core::rootfs_update::{
        RootfsSlot, RootfsUpdateRequest, RootfsUpdateRuntime, UpdateArtifactSet,
    };
    use crate::audit::{AuditEvent, AuditEventType};
    use crate::lifecycle::LifecycleConfig;
    use crate::security_execution::audit::{
        FileRemoteAuditMirror, RemoteAuditFailurePolicy, RemoteAuditMirrorConfig,
    };

    fn test_journal(name: &str) -> AuditJournal {
        let path = std::env::temp_dir().join(format!(
            "agentd-operator-projection-{name}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    fn append_event(
        journal: &AuditJournal,
        event_type: AuditEventType,
        run_id: &str,
        step_id: &str,
        summary: &str,
    ) {
        journal
            .append(&AuditEvent::new(
                event_type, run_id, step_id, "operator", summary,
            ))
            .expect("append event");
    }

    #[test]
    fn combines_health_audit_update_adapter_and_safety_status() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        agentd.record_error("diagnostic failed password=hunter2 secret://prod/db");
        let journal = test_journal("sealed");
        append_event(
            &journal,
            AuditEventType::PlanFrozen,
            "run-operator",
            "plan",
            "plan frozen plan_id=plan-operator plan_hash=hash-operator",
        );
        append_event(
            &journal,
            AuditEventType::EffectPrepared,
            "run-operator",
            "status",
            "prepared tool=svc.status risk=read-only",
        );
        append_event(
            &journal,
            AuditEventType::CommitSealed,
            "run-operator",
            "status",
            "commit sealed tool=svc.status commit_id=commit-operator",
        );

        let projection = OperatorProjection::collect(&agentd, Some(&journal), Some("run-operator"))
            .expect("projection");

        assert!(projection.read_only);
        assert_eq!(projection.runtime.state, "running");
        assert_eq!(projection.audit.audit_seal_status, "sealed");
        assert_eq!(
            projection.audit.latest_run_id.as_deref(),
            Some("run-operator")
        );
        assert_eq!(projection.update.status, "not-configured");
        assert_eq!(projection.adapters.untrusted_content_status, "available");
        assert_eq!(projection.adapters.audit_projection_status, "available");
        assert_eq!(projection.ecosystem.activation_status, "gated");
        assert_eq!(
            projection.ecosystem.activation_authority,
            "AgentCore PlanSpec + SecurityExecutionEngine"
        );
        assert_eq!(projection.ecosystem.local_registry_status, "configured");
        assert_eq!(
            projection.ecosystem.registry_snapshot_digest.as_deref(),
            Some("sha256:agentos-local-alpha-snapshot")
        );
        assert_eq!(projection.ecosystem.registry_artifact_count, 3);
        assert_eq!(projection.ecosystem.core_artifact_count, 3);
        assert!(
            projection
                .ecosystem
                .core_artifacts
                .contains(&"agentos:policy-pack/agentos/core-policy@1.0.0".to_string())
        );
        assert!(
            projection
                .ecosystem
                .blocked_until
                .contains(&"local replay evidence".to_string())
        );
        assert!(
            projection
                .ecosystem
                .required_approvals
                .contains(&"exact approval token for ecosystem.activate".to_string())
        );
        assert!(
            projection
                .ecosystem
                .blocked_reasons
                .contains(&"activation must provide replay and compatibility evidence".to_string())
        );
        assert!(!projection.ecosystem.staged_artifacts_active);
        assert!(projection.ecosystem.staged_and_active_separated);
        assert!(!projection.ecosystem.normal_shell_available);
        assert!(!projection.ecosystem.agentd_resolver_logic);
        assert_eq!(projection.ecosystem.resolver_owner, "agent_core::ecosystem");
        assert_eq!(projection.support_bundle.status, "ready");
        assert_eq!(
            projection.support_bundle.redaction_status,
            "secret-values-redacted"
        );
        assert!(
            projection
                .support_bundle
                .ecosystem_registry_snapshot_hash
                .as_deref()
                .unwrap_or("")
                .starts_with("sha256:agentos-stable-v1-")
        );
        assert!(
            projection
                .support_bundle
                .ecosystem_trust_tiers
                .contains(&"core".to_string())
        );
        assert!(
            !projection
                .support_bundle
                .ecosystem_private_key_paths_included
        );
        assert!(projection.safety.fail_closed);

        let json = projection.to_json();
        assert!(json.contains("\"schema_version\":\"agentd-operator-projection/v1\""));
        assert!(json.contains("\"read_only\":true"));
        assert!(json.contains("\"audit_seal_status\":\"sealed\""));
        assert!(json.contains("\"package_manager_status\":\"available\""));
        assert!(json.contains("\"ecosystem\":{"));
        assert!(json.contains("\"activation_status\":\"gated\""));
        assert!(json.contains("\"registry_artifact_count\":3"));
        assert!(json.contains("\"core_artifact_count\":3"));
        assert!(json.contains("\"required_approvals\":["));
        assert!(json.contains("local replay evidence"));
        assert!(json.contains("\"staged_artifacts_active\":false"));
        assert!(json.contains("\"agentd_resolver_logic\":false"));
        assert!(!json.contains("TASK-ECO-004"));
        assert!(!json.contains("TASK-ECO-005"));
        assert!(json.contains("\"support_bundle\":{"));
        assert!(json.contains("\"bundle_id\":\"support-run-operator\""));
        assert!(json.contains("\"ecosystem_registry_snapshot_hash\":\"sha256:agentos-stable-v1-"));
        assert!(json.contains("\"ecosystem_private_key_paths_included\":false"));
        assert!(json.contains("secret://prod/db"));
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("password=hunter2"));
        assert!(!json.contains("/.ssh/"));
    }

    #[test]
    fn reports_unsealed_audit_without_mutating_journal() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let journal = test_journal("unsealed");
        append_event(
            &journal,
            AuditEventType::EffectPrepared,
            "run-open",
            "write",
            "prepared tool=fs.write.diff risk=write-with-diff",
        );
        let before = journal.event_lines().expect("before projection");

        let projection = OperatorProjection::collect(&agentd, Some(&journal), Some("run-open"))
            .expect("projection");
        let after = journal.event_lines().expect("after projection");

        assert_eq!(before, after);
        assert_eq!(projection.audit.audit_seal_status, "unsealed");
        assert_eq!(projection.audit.unresolved_effects, 1);
        assert_eq!(projection.telemetry.unresolved_effects, 1);
        assert_eq!(projection.audit.effect_prepared_count, 1);
        assert_eq!(projection.audit.commit_sealed_count, 0);
    }

    #[test]
    fn projection_output_is_stable_without_audit_journal() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();

        let projection = OperatorProjection::collect(&agentd, None, None).expect("projection");
        let json = projection.to_json();

        assert!(json.contains("\"latest_run_status\":\"no-run\""));
        assert!(json.contains("\"audit_seal_status\":\"unknown\""));
        assert!(json.contains("\"slot_strategy\":\"ab-rootfs-contract\""));
        let cli = projection.to_cli_text();
        assert!(cli.contains("runtime state=running"));
        assert!(cli.contains("ecosystem registry="));
        assert!(cli.contains("activation_status=gated"));
        assert!(cli.contains("core_artifacts=agentos:policy-pack/agentos/core-policy@1.0.0"));
        assert!(cli.contains("required_approvals=exact approval token for ecosystem.activate"));
        assert!(cli.contains("blocked_until=local replay evidence"));
        assert!(cli.contains("staged_artifacts_active=false"));
    }

    #[test]
    fn redacts_projection_warnings() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let journal = test_journal("warning");
        append_event(
            &journal,
            AuditEventType::RecoveryStarted,
            "run-warning",
            "recover",
            "recovery started",
        );
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(journal.path())
                .expect("open journal");
            writeln!(
                file,
                "{{\"run_id\":\"run-warning\",\"step_id\":\"broken\",\"summary\":\"password=hunter2\"}}"
            )
            .expect("write malformed line");
        }

        let projection = OperatorProjection::collect(&agentd, Some(&journal), Some("run-warning"))
            .expect("projection");
        let json = projection.to_json();

        assert_eq!(projection.audit.warning_count, 1);
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn projection_consumes_update_and_remote_audit_runtime_assertions() {
        let mut agentd = Agentd::new(LifecycleConfig::default());
        agentd.start();
        let root = std::env::temp_dir().join(format!(
            "agentd-operator-projection-runtime-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp dir");
        let journal = AuditJournal::new(root.join("audit.jsonl"));
        let artifacts = UpdateArtifactSet::new(
            "sha256:release-manifest",
            "sha256:rootfs",
            "sha256:provenance",
            "sha256:sbom",
            "sha256:signature",
            "sha256:update-metadata",
        )
        .expect("artifacts");
        let request = RootfsUpdateRequest::new(
            "operator",
            "run-update",
            RootfsSlot::A,
            RootfsSlot::B,
            "file://updates/rootfs.img",
            artifacts,
        )
        .expect("request")
        .with_preflight_verified()
        .with_state_backup_ready();
        RootfsUpdateRuntime
            .stage_update(&journal, &request)
            .expect("stage update");

        let mirror_path = root.join("mirror.jsonl");
        std::fs::write(&mirror_path, "not-json\n").expect("broken mirror");
        FileRemoteAuditMirror::new(mirror_path)
            .mirror_journal(
                &journal,
                &RemoteAuditMirrorConfig::new(RemoteAuditFailurePolicy::FailClosed, "regulated"),
            )
            .expect("mirror failure decision");

        let before = journal.event_lines().expect("before projection");
        let projection = OperatorProjection::collect(&agentd, Some(&journal), Some("run-update"))
            .expect("projection");
        let after = journal.event_lines().expect("after projection");

        assert_eq!(before, after);
        assert_eq!(projection.update.slot_strategy, "ab-rootfs-runtime");
        assert_eq!(projection.update.active_slot, "A");
        assert_eq!(projection.update.inactive_slot, "B");
        assert_eq!(projection.update.status, "activation-scheduled");
        assert!(projection.update.pending_activation);
        assert!(projection.update.assert_ready_for_runbook());
        assert_eq!(projection.audit.remote_mirror_status, "failed-closed");
        assert_eq!(
            projection.audit.remote_mirror_failure_policy.as_deref(),
            Some("fail-closed")
        );
        assert!(
            !projection
                .audit
                .remote_mirror_non_local_side_effects_allowed
        );
        let json = projection.to_json();
        assert!(json.contains("\"remote_mirror_status\":\"failed-closed\""));
        assert!(json.contains("\"slot_strategy\":\"ab-rootfs-runtime\""));
        assert!(!json.contains("not-json"));
    }
}
