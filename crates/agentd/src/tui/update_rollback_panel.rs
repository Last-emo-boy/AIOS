use std::fs;
use std::path::{Path, PathBuf};

use crate::api::escape_json;
use crate::audit::redact_summary;
use crate::runtime_contracts::stable_contract_hash;

use super::release_provenance_panel::{
    DEFAULT_RELEASE_ARTIFACT_DIR, ReleaseProvenancePanel, json_bool, json_object_section,
    json_string, json_string_array, resolve_repo_path,
};

pub const UPDATE_ROLLBACK_PANEL_SCHEMA_VERSION: &str = "agentos.tui-update-rollback-panel.v1";

const UPDATE_METADATA_FILE: &str = "update-metadata.json";
const UPDATE_METADATA_SIGNATURE_FILE: &str = "update-metadata.json.sig.json";

const SCALAR_ARTIFACT_HASHES: &[(&str, &str)] = &[
    ("agentd_binary", "agentd_binary_sha256"),
    ("initramfs", "initramfs_sha256"),
    ("initramfs_manifest", "initramfs_manifest_sha256"),
    ("alpha_rootfs_manifest", "alpha_rootfs_manifest_sha256"),
    ("rootfs_runtime_manifest", "rootfs_runtime_manifest_sha256"),
];

const NESTED_ARTIFACTS: &[&str] = &["active_artifact_set", "ecosystem_replay", "sbom"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRollbackPanel {
    pub schema_version: &'static str,
    pub release_dir: String,
    pub metadata: UpdateMetadataProjection,
    pub strategy: UpdateStrategyProjection,
    pub signature: UpdateMetadataSignatureProjection,
    pub artifacts: Vec<UpdateRollbackArtifactProjection>,
    pub readiness: UpdateReadinessProjection,
    pub slots: Vec<UpdateRollbackSlotProjection>,
    pub blockers: Vec<UpdateRollbackBlocker>,
    pub promotion_status: String,
    pub release_provenance_blocker_count: usize,
}

impl UpdateRollbackPanel {
    pub fn collect() -> Self {
        Self::collect_from_dir(resolve_repo_path(DEFAULT_RELEASE_ARTIFACT_DIR))
    }

    pub fn collect_from_dir(release_dir: impl AsRef<Path>) -> Self {
        let release_dir = release_dir.as_ref().to_path_buf();
        let metadata_path = release_dir.join(UPDATE_METADATA_FILE);
        let metadata_content = fs::read_to_string(&metadata_path).ok();
        let metadata = UpdateMetadataProjection::from_file(&metadata_path, &metadata_content);
        let strategy = UpdateStrategyProjection::from_content(metadata_content.as_deref());
        let signature = UpdateMetadataSignatureProjection::from_release_metadata(
            &release_dir,
            metadata_content.as_deref(),
        );
        let artifacts = collect_artifacts(&release_dir, metadata_content.as_deref());
        let readiness = UpdateReadinessProjection::from_content(metadata_content.as_deref());
        let slots = collect_slots(&metadata_path, &strategy, &readiness);
        let provenance = ReleaseProvenancePanel::collect_from_dir(&release_dir);
        let blockers = collect_blockers(&metadata, &strategy, &signature, &readiness, &provenance);

        Self {
            schema_version: UPDATE_ROLLBACK_PANEL_SCHEMA_VERSION,
            release_dir: release_dir.display().to_string(),
            metadata,
            strategy,
            signature,
            artifacts,
            readiness,
            slots,
            blockers,
            promotion_status: provenance.promotion_status,
            release_provenance_blocker_count: provenance.promotion_blockers.len(),
        }
    }

    pub fn render(&self) -> String {
        let mut lines = vec![
            "TUI Update Rollback".to_string(),
            format!(
                "update_rollback_panel schema={} read_only=true projection_controller_only=true update_authority=false rollback_authority=false direct_update=false direct_rollback=false host_mutation_in_tui=false promotion_blocker_link=\"promotion.blockers.show\" mutation_path=\"AgentCore rootfs_update + SecurityExecutionEngine only\"",
                self.schema_version
            ),
            format!(
                "update_metadata present={} path=\"{}\" schema=\"{}\" generated_at=\"{}\" metadata_hash=\"{}\" production_ready_claim={} source_commit=\"{}\" source_branch=\"{}\"",
                self.metadata.present,
                safe_text(&self.metadata.path),
                safe_text(&self.metadata.schema),
                safe_text(&self.metadata.generated_at),
                safe_text(&self.metadata.metadata_hash),
                self.metadata.production_ready_claim,
                safe_text(&self.metadata.source_commit),
                safe_text(&self.metadata.source_branch)
            ),
            format!(
                "update_metadata_signature present={} status={} path=\"{}\" signature_policy_status=\"{}\" artifact_sha256=\"{}\" signature_hash=\"{}\" key_id=\"{}\" algorithm=\"{}\" production_key_required={} unsigned_metadata_acceptable=false",
                self.signature.present,
                safe_text(&self.signature.status),
                safe_text(&self.signature.path),
                safe_text(&self.signature.policy_status),
                safe_text(&self.signature.artifact_sha256),
                safe_text(&self.signature.signature_hash),
                safe_text(&self.signature.key_id),
                safe_text(&self.signature.algorithm),
                self.signature.production_key_required
            ),
            format!(
                "update_strategy mode=\"{}\" stage_target=\"{}\" active_slot_modified_in_place={} health_gate_required={} rollback_required={} operations_preview_only=true active_slot_write_allowed=false",
                safe_text(&self.strategy.mode),
                safe_text(&self.strategy.stage_target),
                self.strategy.active_slot_modified_in_place,
                self.strategy.health_gate_required,
                self.strategy.rollback_required
            ),
            format!(
                "slot_summary active_slot={} pending_slot={} rollback_slot={} active_slot_evidence_path=\"{}\" pending_slot_evidence_path=\"{}\" rollback_slot_evidence_path=\"{}\" previous_active_set_preserved={} previous_equals_restored={}",
                safe_text(&self.active_slot_label()),
                safe_text(&self.pending_slot_label()),
                safe_text(&self.rollback_slot_label()),
                safe_text(&self.readiness.active_artifact_set_path),
                safe_text(&self.metadata.path),
                safe_text(&self.metadata.path),
                self.readiness.rollback_preserves_previous_active_set,
                self.readiness.previous_equals_restored()
            ),
            format!(
                "health_gate state={} active_artifact_set_present={} runtime_contract_compatibility_checked={} ecosystem_replay_status=\"{}\" promotion_allowed={} incompatible_active_artifact_count={} failed_visible={} safe_next_command=\"promotion.blockers.show\"",
                safe_text(self.readiness.health_state()),
                self.readiness.active_artifact_set_present,
                self.readiness.runtime_contract_compatibility_checked,
                safe_text(&self.readiness.ecosystem_replay_status),
                self.readiness.promotion_allowed,
                self.readiness.incompatible_active_artifacts.len(),
                self.readiness.health_state() != "passed",
            ),
            format!(
                "rollback_drill status={} rollback_preserves_previous_active_set={} previous_active_set_hash=\"{}\" restored_active_set_hash=\"{}\" previous_equals_restored={} safe_next_command=\"promotion.blockers.show\"",
                safe_text(self.readiness.rollback_drill_status()),
                self.readiness.rollback_preserves_previous_active_set,
                safe_text(&self.readiness.previous_active_set_hash),
                safe_text(&self.readiness.restored_active_set_hash),
                self.readiness.previous_equals_restored()
            ),
            format!(
                "failure_link blocker_count={} release_provenance_blocker_count={} promotion_status={} blockers=\"{}\" safe_next_command=\"promotion.blockers.show\"",
                self.blockers.len(),
                self.release_provenance_blocker_count,
                safe_text(&self.promotion_status),
                safe_join_blockers(&self.blockers)
            ),
            "update_invariants artifact_generation_in_tui=false update_metadata_mutation_in_tui=false slot_mutation_in_tui=false rollback_execution_in_tui=false promotion_blocker_clear_in_tui=false hashes_and_paths_only=true".to_string(),
        ];
        lines.extend(self.slots.iter().map(UpdateRollbackSlotProjection::render));
        lines.extend(
            self.artifacts
                .iter()
                .map(UpdateRollbackArtifactProjection::render),
        );
        if self.blockers.is_empty() {
            lines.push("update_blocker id=none severity=none status=clear evidence_path=\"-\" safe_next_command=\"promotion.blockers.show\" message=\"no update or rollback blockers in current metadata\"".to_string());
        } else {
            lines.extend(self.blockers.iter().map(UpdateRollbackBlocker::render));
        }
        lines.join("\n")
    }

    fn active_slot_label(&self) -> String {
        if self.readiness.active_artifact_set_present {
            "active-artifact-set".to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn pending_slot_label(&self) -> String {
        if self.strategy.stage_target == "-" || self.strategy.stage_target == "missing" {
            "unknown".to_string()
        } else {
            self.strategy.stage_target.clone()
        }
    }

    fn rollback_slot_label(&self) -> String {
        if self.strategy.rollback_required {
            "previous-active-set".to_string()
        } else {
            "none".to_string()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMetadataProjection {
    pub path: String,
    pub present: bool,
    pub schema: String,
    pub generated_at: String,
    pub metadata_hash: String,
    pub production_ready_claim: bool,
    pub source_commit: String,
    pub source_branch: String,
}

impl UpdateMetadataProjection {
    fn from_file(path: &Path, content: &Option<String>) -> Self {
        let source = content
            .as_deref()
            .and_then(|content| json_object_section(content, "source"))
            .unwrap_or_default();
        Self {
            path: path.display().to_string(),
            present: content.is_some(),
            schema: content
                .as_deref()
                .and_then(|content| json_string(content, "schema"))
                .unwrap_or_else(|| "missing".to_string()),
            generated_at: content
                .as_deref()
                .and_then(|content| json_string(content, "generated_at"))
                .unwrap_or_else(|| "missing".to_string()),
            metadata_hash: content
                .as_deref()
                .map(stable_contract_hash)
                .unwrap_or_else(|| "missing".to_string()),
            production_ready_claim: content
                .as_deref()
                .and_then(|content| json_bool(content, "production_ready_claim"))
                .unwrap_or(false),
            source_commit: json_string(&source, "git_commit").unwrap_or_else(|| "-".to_string()),
            source_branch: json_string(&source, "git_branch").unwrap_or_else(|| "-".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateStrategyProjection {
    pub mode: String,
    pub stage_target: String,
    pub active_slot_modified_in_place: bool,
    pub health_gate_required: bool,
    pub rollback_required: bool,
}

impl UpdateStrategyProjection {
    fn from_content(content: Option<&str>) -> Self {
        let strategy = content
            .and_then(|content| json_object_section(content, "update_strategy"))
            .unwrap_or_default();
        Self {
            mode: json_string(&strategy, "mode").unwrap_or_else(|| "missing".to_string()),
            stage_target: json_string(&strategy, "stage_target")
                .unwrap_or_else(|| "missing".to_string()),
            active_slot_modified_in_place: json_bool(&strategy, "active_slot_modified_in_place")
                .unwrap_or(true),
            health_gate_required: json_bool(&strategy, "health_gate_required").unwrap_or(false),
            rollback_required: json_bool(&strategy, "rollback_required").unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMetadataSignatureProjection {
    pub path: String,
    pub present: bool,
    pub status: String,
    pub policy_status: String,
    pub artifact_sha256: String,
    pub signature_hash: String,
    pub key_id: String,
    pub algorithm: String,
    pub production_key_required: bool,
}

impl UpdateMetadataSignatureProjection {
    fn from_file(path: &Path) -> Self {
        let content = fs::read_to_string(path).ok();
        let artifact = content
            .as_deref()
            .and_then(|content| json_object_section(content, "artifact"))
            .unwrap_or_default();
        let signature = content
            .as_deref()
            .and_then(|content| json_object_section(content, "signature"))
            .unwrap_or_default();
        let key = content
            .as_deref()
            .and_then(|content| json_object_section(content, "key"))
            .unwrap_or_default();
        let present = content.is_some();
        Self {
            path: path.display().to_string(),
            present,
            status: if present { "present" } else { "missing" }.to_string(),
            policy_status: "missing".to_string(),
            artifact_sha256: json_string(&artifact, "sha256")
                .unwrap_or_else(|| "missing".to_string()),
            signature_hash: json_string(&signature, "value")
                .unwrap_or_else(|| "missing".to_string()),
            key_id: json_string(&key, "key_id").unwrap_or_else(|| "missing".to_string()),
            algorithm: json_string(&signature, "algorithm")
                .unwrap_or_else(|| "missing".to_string()),
            production_key_required: json_bool(&key, "production_key_required").unwrap_or(false),
        }
    }

    fn with_policy_status(mut self, policy_status: impl Into<String>) -> Self {
        self.policy_status = policy_status.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRollbackArtifactProjection {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub present: bool,
    pub required: bool,
    pub status: String,
    pub source: String,
}

impl UpdateRollbackArtifactProjection {
    fn render(&self) -> String {
        format!(
            "update_artifact name={} status={} present={} required={} source={} path=\"{}\" sha256=\"{}\"",
            safe_text(&self.name),
            safe_text(&self.status),
            self.present,
            self.required,
            safe_text(&self.source),
            safe_text(&self.path),
            safe_text(&self.sha256)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReadinessProjection {
    pub active_artifact_set_hash: String,
    pub active_artifact_set_path: String,
    pub active_artifact_set_present: bool,
    pub runtime_contract_compatibility_checked: bool,
    pub incompatible_active_artifacts: Vec<String>,
    pub rollback_preserves_previous_active_set: bool,
    pub previous_active_set_hash: String,
    pub restored_active_set_hash: String,
    pub ecosystem_replay_status: String,
    pub promotion_allowed: bool,
}

impl UpdateReadinessProjection {
    fn from_content(content: Option<&str>) -> Self {
        let readiness = content
            .and_then(|content| json_object_section(content, "update_readiness"))
            .unwrap_or_default();
        Self {
            active_artifact_set_hash: json_string(&readiness, "active_artifact_set_hash")
                .unwrap_or_else(|| "missing".to_string()),
            active_artifact_set_path: json_string(&readiness, "active_artifact_set_path")
                .unwrap_or_else(|| "-".to_string()),
            active_artifact_set_present: json_bool(&readiness, "active_artifact_set_present")
                .unwrap_or(false),
            runtime_contract_compatibility_checked: json_bool(
                &readiness,
                "runtime_contract_compatibility_checked",
            )
            .unwrap_or(false),
            incompatible_active_artifacts: json_string_array(
                &readiness,
                "incompatible_active_artifacts",
            ),
            rollback_preserves_previous_active_set: json_bool(
                &readiness,
                "rollback_preserves_previous_active_set",
            )
            .unwrap_or(false),
            previous_active_set_hash: json_string(&readiness, "previous_active_set_hash")
                .unwrap_or_else(|| "missing".to_string()),
            restored_active_set_hash: json_string(&readiness, "restored_active_set_hash")
                .unwrap_or_else(|| "missing".to_string()),
            ecosystem_replay_status: json_string(&readiness, "ecosystem_replay_status")
                .unwrap_or_else(|| "missing".to_string()),
            promotion_allowed: json_bool(&readiness, "promotion_allowed").unwrap_or(false),
        }
    }

    fn health_state(&self) -> &'static str {
        if self.active_artifact_set_present
            && self.runtime_contract_compatibility_checked
            && self.incompatible_active_artifacts.is_empty()
            && self.ecosystem_replay_status == "passed"
            && self.promotion_allowed
        {
            "passed"
        } else {
            "blocked"
        }
    }

    fn rollback_drill_status(&self) -> &'static str {
        if self.rollback_preserves_previous_active_set && self.previous_equals_restored() {
            "passed"
        } else {
            "blocked"
        }
    }

    fn previous_equals_restored(&self) -> bool {
        self.previous_active_set_hash != "missing"
            && self.previous_active_set_hash == self.restored_active_set_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRollbackSlotProjection {
    pub role: String,
    pub slot: String,
    pub status: String,
    pub evidence_path: String,
    pub artifact_hash: String,
    pub source: String,
}

impl UpdateRollbackSlotProjection {
    fn render(&self) -> String {
        format!(
            "slot_evidence role={} slot={} status={} source=\"{}\" evidence_path=\"{}\" artifact_hash=\"{}\" host_mutation=false",
            safe_text(&self.role),
            safe_text(&self.slot),
            safe_text(&self.status),
            safe_text(&self.source),
            safe_text(&self.evidence_path),
            safe_text(&self.artifact_hash)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRollbackBlocker {
    pub id: String,
    pub severity: String,
    pub status: String,
    pub evidence_path: String,
    pub safe_next_command: String,
    pub message: String,
}

impl UpdateRollbackBlocker {
    fn new(
        id: impl Into<String>,
        status: impl Into<String>,
        evidence_path: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let status = status.into();
        Self {
            message: blocker_message(&id, &status),
            id,
            severity: "blocking".to_string(),
            status,
            evidence_path: evidence_path.into(),
            safe_next_command: "promotion.blockers.show".to_string(),
        }
    }

    fn render(&self) -> String {
        format!(
            "update_blocker id=\"{}\" severity={} status={} evidence_path=\"{}\" safe_next_command=\"{}\" message=\"{}\"",
            safe_text(&self.id),
            safe_text(&self.severity),
            safe_text(&self.status),
            safe_text(&self.evidence_path),
            safe_text(&self.safe_next_command),
            safe_text(&self.message)
        )
    }
}

fn collect_artifacts(
    release_dir: &Path,
    metadata_content: Option<&str>,
) -> Vec<UpdateRollbackArtifactProjection> {
    let artifacts_object = metadata_content
        .and_then(|content| json_object_section(content, "artifacts"))
        .unwrap_or_default();
    let mut artifacts = SCALAR_ARTIFACT_HASHES
        .iter()
        .map(|(name, key)| {
            let sha256 =
                json_string(&artifacts_object, key).unwrap_or_else(|| "missing".to_string());
            UpdateRollbackArtifactProjection {
                name: (*name).to_string(),
                path: "-".to_string(),
                present: sha256 != "missing",
                required: true,
                status: if sha256 == "missing" {
                    "missing"
                } else {
                    "recorded"
                }
                .to_string(),
                sha256,
                source: "update-metadata".to_string(),
            }
        })
        .collect::<Vec<_>>();
    artifacts.extend(NESTED_ARTIFACTS.iter().map(|name| {
        let object = json_object_section(&artifacts_object, name).unwrap_or_default();
        let path = json_string(&object, "path").unwrap_or_else(|| "-".to_string());
        let sha256 = json_string(&object, "sha256").unwrap_or_else(|| "missing".to_string());
        let required = json_bool(&object, "required").unwrap_or(*name != "sbom");
        let present = resolve_artifact_path(release_dir, &path)
            .map(|path| path.exists())
            .unwrap_or(false);
        let status = if object.is_empty() || sha256 == "missing" {
            "missing"
        } else if required && !present {
            "missing-file"
        } else {
            "recorded"
        };
        UpdateRollbackArtifactProjection {
            name: (*name).to_string(),
            path,
            sha256,
            present,
            required,
            status: status.to_string(),
            source: "update-metadata".to_string(),
        }
    }));
    artifacts
}

fn collect_slots(
    metadata_path: &Path,
    strategy: &UpdateStrategyProjection,
    readiness: &UpdateReadinessProjection,
) -> Vec<UpdateRollbackSlotProjection> {
    vec![
        UpdateRollbackSlotProjection {
            role: "active".to_string(),
            slot: if readiness.active_artifact_set_present {
                "active-artifact-set".to_string()
            } else {
                "unknown".to_string()
            },
            status: if readiness.active_artifact_set_present {
                "present"
            } else {
                "missing"
            }
            .to_string(),
            evidence_path: readiness.active_artifact_set_path.clone(),
            artifact_hash: readiness.active_artifact_set_hash.clone(),
            source: "update_readiness.active_artifact_set".to_string(),
        },
        UpdateRollbackSlotProjection {
            role: "pending".to_string(),
            slot: strategy.stage_target.clone(),
            status: if strategy.stage_target == "inactive-slot" {
                "stage-target"
            } else {
                "unknown"
            }
            .to_string(),
            evidence_path: metadata_path.display().to_string(),
            artifact_hash: "-".to_string(),
            source: "update_strategy.stage_target".to_string(),
        },
        UpdateRollbackSlotProjection {
            role: "rollback".to_string(),
            slot: if strategy.rollback_required {
                "previous-active-set".to_string()
            } else {
                "none".to_string()
            },
            status: readiness.rollback_drill_status().to_string(),
            evidence_path: metadata_path.display().to_string(),
            artifact_hash: readiness.previous_active_set_hash.clone(),
            source: "update_readiness.rollback_preserves_previous_active_set".to_string(),
        },
    ]
}

fn collect_blockers(
    metadata: &UpdateMetadataProjection,
    strategy: &UpdateStrategyProjection,
    signature: &UpdateMetadataSignatureProjection,
    readiness: &UpdateReadinessProjection,
    provenance: &ReleaseProvenancePanel,
) -> Vec<UpdateRollbackBlocker> {
    let mut blockers = Vec::new();
    let metadata_path = metadata.path.clone();
    if !metadata.present {
        blockers.push(UpdateRollbackBlocker::new(
            "update-metadata-missing",
            "missing-evidence",
            &metadata_path,
        ));
    }
    if !signature.present {
        blockers.push(UpdateRollbackBlocker::new(
            "update-metadata-signature-missing",
            "missing-evidence",
            &signature.path,
        ));
    }
    if signature.policy_status != "candidate-hash-bound" {
        blockers.push(UpdateRollbackBlocker::new(
            "update-metadata-signature-policy-unacceptable",
            "unsigned-or-unbound-metadata",
            &metadata_path,
        ));
    }
    if strategy.mode != "ab-rootfs" {
        blockers.push(UpdateRollbackBlocker::new(
            "update-strategy-not-ab-rootfs",
            "invalid-update-strategy",
            &metadata_path,
        ));
    }
    if strategy.stage_target != "inactive-slot" {
        blockers.push(UpdateRollbackBlocker::new(
            "update-stage-target-not-inactive-slot",
            "active-slot-risk",
            &metadata_path,
        ));
    }
    if strategy.active_slot_modified_in_place {
        blockers.push(UpdateRollbackBlocker::new(
            "active-slot-modified-in-place",
            "active-slot-risk",
            &metadata_path,
        ));
    }
    if !strategy.health_gate_required {
        blockers.push(UpdateRollbackBlocker::new(
            "pending-slot-health-gate-not-required",
            "missing-gate",
            &metadata_path,
        ));
    }
    if !strategy.rollback_required {
        blockers.push(UpdateRollbackBlocker::new(
            "rollback-not-required",
            "missing-gate",
            &metadata_path,
        ));
    }
    if !readiness.active_artifact_set_present {
        blockers.push(UpdateRollbackBlocker::new(
            "active-artifact-set-missing",
            "missing-evidence",
            &readiness.active_artifact_set_path,
        ));
    }
    if !readiness.runtime_contract_compatibility_checked {
        blockers.push(UpdateRollbackBlocker::new(
            "runtime-contract-compatibility-not-checked",
            "missing-gate",
            &metadata_path,
        ));
    }
    if !readiness.incompatible_active_artifacts.is_empty() {
        blockers.push(UpdateRollbackBlocker::new(
            "incompatible-active-artifacts",
            "failed-gate",
            &metadata_path,
        ));
    }
    if readiness.ecosystem_replay_status != "passed" {
        blockers.push(UpdateRollbackBlocker::new(
            "ecosystem-replay-not-passed",
            "failed-gate",
            ".workflow/artifacts/ecosystem-replay/result.json",
        ));
    }
    if !readiness.promotion_allowed {
        blockers.push(UpdateRollbackBlocker::new(
            "update-readiness-promotion-not-allowed",
            "blocked",
            &metadata_path,
        ));
    }
    if readiness.rollback_drill_status() != "passed" {
        blockers.push(UpdateRollbackBlocker::new(
            "rollback-preservation-failed",
            "failed-gate",
            &metadata_path,
        ));
    }
    blockers.extend(provenance.promotion_blockers.iter().map(|blocker| {
        UpdateRollbackBlocker::new(
            format!("release-provenance:{blocker}"),
            "release-provenance-blocker",
            &provenance.provenance_path,
        )
    }));
    blockers.sort_by(|left, right| left.id.cmp(&right.id));
    blockers
}

fn blocker_message(id: &str, status: &str) -> String {
    match status {
        "missing-evidence" => format!("required update or rollback evidence is missing: {id}"),
        "missing-gate" => format!("required update or rollback gate is missing: {id}"),
        "failed-gate" => format!("update or rollback gate failed: {id}"),
        "active-slot-risk" => format!("update metadata indicates active slot mutation risk: {id}"),
        "unsigned-or-unbound-metadata" => {
            format!("update metadata signature policy is not acceptable: {id}")
        }
        "release-provenance-blocker" => {
            format!("release provenance still reports a blocker: {id}")
        }
        _ => format!("update or rollback readiness is blocked: {id}"),
    }
}

fn resolve_artifact_path(release_dir: &Path, value: &str) -> Option<PathBuf> {
    if value.trim().is_empty() || value == "-" {
        return None;
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else if path.components().count() == 1 {
        Some(release_dir.join(path))
    } else {
        Some(resolve_repo_path(value))
    }
}

fn safe_join_blockers(blockers: &[UpdateRollbackBlocker]) -> String {
    if blockers.is_empty() {
        "-".to_string()
    } else {
        safe_text(
            &blockers
                .iter()
                .map(|blocker| blocker.id.as_str())
                .collect::<Vec<_>>()
                .join("|"),
        )
    }
}

fn safe_text(value: &str) -> String {
    escape_json(&redact_summary(value))
}

impl UpdateMetadataSignatureProjection {
    pub(crate) fn from_release_metadata(
        release_dir: &Path,
        metadata_content: Option<&str>,
    ) -> Self {
        let policy_status = metadata_content
            .and_then(|content| json_object_section(content, "signature_policy"))
            .and_then(|section| json_string(&section, "status"))
            .unwrap_or_else(|| "missing".to_string());
        Self::from_file(&release_dir.join(UPDATE_METADATA_SIGNATURE_FILE))
            .with_policy_status(policy_status)
    }
}
