use std::fs;
use std::path::Path;

use crate::api::escape_json;
use crate::audit::redact_summary;

use super::release_provenance_panel::{json_array_section, json_string, resolve_repo_path};

pub const ROLLOUT_RING_PANEL_SCHEMA_VERSION: &str = "agentos.tui-rollout-ring-panel.v1";

const DEFAULT_ARTIFACT_ROOT: &str = ".workflow/artifacts";
const LOCAL_FLEET_MODEL_DOC: &str = ".workflow/active/WFS-20260525-agentos-console-beta-production-ux/docs/local-first-fleet-operations.md";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutRingPanel {
    pub schema_version: &'static str,
    pub artifact_root: String,
    pub local_fleet_model_path: String,
    pub evidence: RolloutEvidence,
    pub rings: Vec<RolloutRingItem>,
    pub blockers: Vec<RolloutRingBlocker>,
}

impl RolloutRingPanel {
    pub fn collect() -> Self {
        Self::collect_from_artifact_root(resolve_repo_path(DEFAULT_ARTIFACT_ROOT))
    }

    pub fn collect_from_artifact_root(artifact_root: impl AsRef<Path>) -> Self {
        let artifact_root = artifact_root.as_ref().to_path_buf();
        let evidence = RolloutEvidence::collect(&artifact_root);
        let rings = rollout_rings(&evidence);
        let blockers = rings
            .iter()
            .flat_map(|ring| ring.blockers.clone())
            .collect::<Vec<_>>();
        Self {
            schema_version: ROLLOUT_RING_PANEL_SCHEMA_VERSION,
            artifact_root: artifact_root.display().to_string(),
            local_fleet_model_path: LOCAL_FLEET_MODEL_DOC.to_string(),
            evidence,
            rings,
            blockers,
        }
    }

    pub fn render(&self) -> String {
        let total_nodes = self.rings.iter().map(|ring| ring.node_count).sum::<usize>();
        let local_ready = self
            .rings
            .iter()
            .any(|ring| ring.name == "local" && ring.status == "local-proof-ready");
        let mut lines = vec![
            "TUI Rollout Rings".to_string(),
            format!(
                "rollout_ring_panel schema={} read_only=true projection_controller_only=true preview_only=true fleet_manager=false remote_rollout_authority=false direct_rollout=false remote_command_dispatch=false local_agentcore_required=true security_execution_required=true",
                self.schema_version
            ),
            format!(
                "rollout_summary status=preview-only ring_count={} total_nodes={} local_only_baseline=true local_proof_ready={} production_ready_claim=false remote_services_required=false blocker_count={} artifact_root=\"{}\"",
                self.rings.len(),
                total_nodes,
                local_ready,
                self.blockers.len(),
                safe_text(&self.artifact_root)
            ),
            format!(
                "rollout_sources local_fleet_model=\"{}\" release_provenance_present={} tui_replay_status={} production_runbook_status={} ecosystem_replay_status={} production_signature_verification_status={} production_ready_claim={}",
                safe_text(&self.local_fleet_model_path),
                self.evidence.release_provenance_present,
                safe_text(&self.evidence.tui_replay_status),
                safe_text(&self.evidence.production_runbook_status),
                safe_text(&self.evidence.ecosystem_replay_status),
                safe_text(&self.evidence.production_signature_verification_status),
                self.evidence.production_ready_claim
            ),
            "rollout_invariants rollout_execution_in_tui=false remote_rollout_execution_in_tui=false rollout_mutation_in_tui=false remote_operator_bypass=false production_promotion_in_tui=false rollback_execution_in_tui=false fixture_projection_only=true".to_string(),
        ];
        lines.extend(self.rings.iter().map(RolloutRingItem::render));
        lines.extend(self.blockers.iter().map(RolloutRingBlocker::render));
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutEvidence {
    pub release_provenance_present: bool,
    pub tui_replay_status: String,
    pub production_runbook_status: String,
    pub ecosystem_replay_status: String,
    pub production_signature_verification_status: String,
    pub production_ready_claim: bool,
    pub production_signature_blockers: usize,
}

impl RolloutEvidence {
    fn collect(artifact_root: &Path) -> Self {
        let release_provenance_path = artifact_root.join("release").join("provenance.json");
        let tui_replay = read_optional(&artifact_root.join("tui-replay").join("result.json"));
        let production_runbook = read_optional(
            &artifact_root
                .join("production-runbook-smoke")
                .join("result.json"),
        );
        let ecosystem_replay =
            read_optional(&artifact_root.join("ecosystem-replay").join("result.json"));
        let production_signature_verification = read_optional(
            &artifact_root
                .join("production-signature-verification")
                .join("result.json"),
        );
        Self {
            release_provenance_present: release_provenance_path.is_file(),
            tui_replay_status: status_or_result(&tui_replay),
            production_runbook_status: status_or_result(&production_runbook),
            ecosystem_replay_status: status_or_result(&ecosystem_replay),
            production_signature_verification_status: status_or_result(
                &production_signature_verification,
            ),
            production_ready_claim: production_signature_verification
                .as_deref()
                .and_then(|content| bool_value(content, "production_ready_claim"))
                .unwrap_or(false),
            production_signature_blockers: production_signature_verification
                .as_deref()
                .and_then(|content| json_array_section(content, "blockers"))
                .map(|blockers| blockers.matches('{').count())
                .unwrap_or(0),
        }
    }

    fn local_gate_passed(&self) -> bool {
        self.release_provenance_present
            && self.tui_replay_status == "passed"
            && self.production_runbook_status == "passed"
            && self.ecosystem_replay_status == "passed"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutRingItem {
    pub name: &'static str,
    pub label: &'static str,
    pub status: String,
    pub node_count: usize,
    pub gate_status: String,
    pub rollback_readiness: String,
    pub evidence_path: String,
    pub safe_next_command: &'static str,
    pub blockers: Vec<RolloutRingBlocker>,
}

impl RolloutRingItem {
    fn render(&self) -> String {
        format!(
            "rollout_ring name={} label=\"{}\" status={} preview_only=true node_count={} gate_status={} rollback_readiness={} blockers=\"{}\" evidence_path=\"{}\" safe_next_command=\"{}\" remote_execution_allowed=false command_enabled=false",
            safe_text(self.name),
            safe_text(self.label),
            safe_text(&self.status),
            self.node_count,
            safe_text(&self.gate_status),
            safe_text(&self.rollback_readiness),
            safe_join(
                &self
                    .blockers
                    .iter()
                    .map(|blocker| blocker.id.clone())
                    .collect::<Vec<_>>()
            ),
            safe_text(&self.evidence_path),
            safe_text(self.safe_next_command)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutRingBlocker {
    pub id: String,
    pub ring: String,
    pub severity: String,
    pub status: String,
    pub evidence_path: String,
    pub safe_next_command: String,
    pub message: String,
}

impl RolloutRingBlocker {
    fn new(
        id: impl Into<String>,
        ring: impl Into<String>,
        status: impl Into<String>,
        evidence_path: impl Into<String>,
        safe_next_command: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            ring: ring.into(),
            severity: "blocking".to_string(),
            status: status.into(),
            evidence_path: evidence_path.into(),
            safe_next_command: safe_next_command.into(),
            message: message.into(),
        }
    }

    fn render(&self) -> String {
        format!(
            "rollout_blocker id=\"{}\" ring={} severity={} status={} evidence_path=\"{}\" safe_next_command=\"{}\" message=\"{}\"",
            safe_text(&self.id),
            safe_text(&self.ring),
            safe_text(&self.severity),
            safe_text(&self.status),
            safe_text(&self.evidence_path),
            safe_text(&self.safe_next_command),
            safe_text(&self.message)
        )
    }
}

fn rollout_rings(evidence: &RolloutEvidence) -> Vec<RolloutRingItem> {
    let mut rings = Vec::new();
    let mut local_blockers = Vec::new();
    if !evidence.local_gate_passed() {
        local_blockers.push(RolloutRingBlocker::new(
            "local-proof-gates-not-passed",
            "local",
            "blocked",
            ".workflow/artifacts",
            "gate.status.show",
            "single-node local proof gates must pass before fleet preview can advance",
        ));
    }
    rings.push(RolloutRingItem {
        name: "local",
        label: "Local Proof",
        status: if local_blockers.is_empty() {
            "local-proof-ready".to_string()
        } else {
            "blocked".to_string()
        },
        node_count: 1,
        gate_status: if local_blockers.is_empty() {
            "passed".to_string()
        } else {
            "blocked".to_string()
        },
        rollback_readiness: if evidence.production_runbook_status == "passed" {
            "local-rollback-evidence-present".to_string()
        } else {
            "blocked".to_string()
        },
        evidence_path: ".workflow/artifacts".to_string(),
        safe_next_command: "gate.status.show",
        blockers: local_blockers,
    });

    rings.push(preview_ring(
        "canary",
        "Canary Preview",
        0,
        "requires-local-node-opt-in",
        vec![RolloutRingBlocker::new(
            "remote-fleet-authority-not-implemented",
            "canary",
            "preview-only",
            LOCAL_FLEET_MODEL_DOC,
            "rollout.rings.show",
            "Console Beta does not implement remote fleet rollout authority",
        )],
    ));
    rings.push(preview_ring(
        "staging",
        "Staging Preview",
        0,
        "requires-ring-health-and-rollback-drill",
        vec![
            RolloutRingBlocker::new(
                "multi-node-health-gate-missing",
                "staging",
                "preview-only",
                LOCAL_FLEET_MODEL_DOC,
                "rollout.rings.show",
                "multi-node health gates are future work and cannot be implied by local proof",
            ),
            RolloutRingBlocker::new(
                "multi-node-rollback-drill-missing",
                "staging",
                "preview-only",
                LOCAL_FLEET_MODEL_DOC,
                "rollout.rings.show",
                "ring rollback drill evidence is required before staging rollout",
            ),
        ],
    ));

    let mut production_blockers = vec![RolloutRingBlocker::new(
        "production-rollout-authority-not-implemented",
        "production",
        "preview-only",
        LOCAL_FLEET_MODEL_DOC,
        "rollout.rings.show",
        "Console Beta cannot claim production fleet rollout authority",
    )];
    if evidence.production_signature_verification_status != "passed"
        || evidence.production_ready_claim
    {
        production_blockers.push(RolloutRingBlocker::new(
            "production-signatures-not-verified",
            "production",
            evidence.production_signature_verification_status.clone(),
            ".workflow/artifacts/production-signature-verification/result.json",
            "signing.status.show",
            "production rollout requires production signature verification, not candidate signatures",
        ));
    }
    if evidence.production_signature_blockers > 0 {
        production_blockers.push(RolloutRingBlocker::new(
            "production-signature-blockers-present",
            "production",
            "blocked",
            ".workflow/artifacts/production-signature-verification/result.json",
            "signing.status.show",
            "production signature verification has blocking findings",
        ));
    }
    rings.push(preview_ring(
        "production",
        "Production Preview",
        0,
        "blocked-until-production-signatures-and-rollout-drill",
        production_blockers,
    ));
    rings
}

fn preview_ring(
    name: &'static str,
    label: &'static str,
    node_count: usize,
    rollback_readiness: &'static str,
    blockers: Vec<RolloutRingBlocker>,
) -> RolloutRingItem {
    RolloutRingItem {
        name,
        label,
        status: "preview-blocked".to_string(),
        node_count,
        gate_status: "preview-only".to_string(),
        rollback_readiness: rollback_readiness.to_string(),
        evidence_path: LOCAL_FLEET_MODEL_DOC.to_string(),
        safe_next_command: "rollout.rings.show",
        blockers,
    }
}

fn status_or_result(content: &Option<String>) -> String {
    content
        .as_deref()
        .and_then(|content| {
            json_string(content, "status").or_else(|| json_string(content, "result"))
        })
        .unwrap_or_else(|| "missing".to_string())
}

fn bool_value(content: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let start = content.find(&needle)? + needle.len();
    let colon_relative = content[start..].find(':')?;
    let value = content[start + colon_relative + 1..].trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn read_optional(path: &Path) -> Option<String> {
    let path = if path.exists() {
        path.to_path_buf()
    } else {
        resolve_repo_path(path)
    };
    fs::read_to_string(path).ok()
}

fn safe_join(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        safe_text(&values.join("|"))
    }
}

fn safe_text(value: &str) -> String {
    escape_json(&redact_summary(value))
}
