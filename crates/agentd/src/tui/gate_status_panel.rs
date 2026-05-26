use std::fs;
use std::path::{Path, PathBuf};

use crate::api::escape_json;
use crate::audit::redact_summary;

use super::release_provenance_panel::{
    DEFAULT_RELEASE_ARTIFACT_DIR, json_bool, json_object_section, json_string, json_string_array,
    resolve_repo_path,
};

pub const GATE_STATUS_PANEL_SCHEMA_VERSION: &str = "agentos.tui-gate-status-panel.v1";

const PROVENANCE_FILE: &str = "provenance.json";
const REQUIRED_RUNTIME_MARKERS: &[&str] = &[
    "AGENTD_HANDOFF_OK",
    "AGENTOS_RUNTIME_ARTIFACTS_OK",
    "AGENTOS_TUI_CONSOLE_READY",
];

const GATE_SPECS: &[GateSpec] = &[
    GateSpec {
        name: "qemu_runtime_smoke",
        default_path: ".workflow/artifacts/boot/boot-smoke-result.json",
        command: "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath E:\\qemu\\qemu-system-x86_64.exe -TimeoutSeconds 120",
        status_kind: GateStatusKind::QemuBoot,
    },
    GateSpec {
        name: "alpha_rootfs_validation",
        default_path: "image/out/agentos-alpha-rootfs.validation.json",
        command: "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/validate-alpha-rootfs.ps1",
        status_kind: GateStatusKind::ResultField,
    },
    GateSpec {
        name: "functional_capability_replay",
        default_path: ".workflow/artifacts/functional-replay/result.json",
        command: "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/functional-capability-replay.ps1",
        status_kind: GateStatusKind::StatusField,
    },
    GateSpec {
        name: "ecosystem_replay",
        default_path: ".workflow/artifacts/ecosystem-replay/result.json",
        command: "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/ecosystem-replay.ps1",
        status_kind: GateStatusKind::StatusField,
    },
    GateSpec {
        name: "tui_replay",
        default_path: ".workflow/artifacts/tui-replay/result.json",
        command: "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/tui-replay.ps1",
        status_kind: GateStatusKind::StatusField,
    },
    GateSpec {
        name: "production_runbook_smoke",
        default_path: ".workflow/artifacts/production-runbook-smoke/result.json",
        command: "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/production-runbook-smoke.ps1",
        status_kind: GateStatusKind::ResultField,
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateStatusPanel {
    pub schema_version: &'static str,
    pub release_dir: String,
    pub provenance_path: String,
    pub provenance_present: bool,
    pub rootfs: RootfsManifestProjection,
    pub qemu: QemuGateProjection,
    pub gates: Vec<GateProjection>,
    pub blockers: Vec<GateBlocker>,
}

impl GateStatusPanel {
    pub fn collect() -> Self {
        Self::collect_from_dir(resolve_repo_path(DEFAULT_RELEASE_ARTIFACT_DIR))
    }

    pub fn collect_from_dir(release_dir: impl AsRef<Path>) -> Self {
        let release_dir = release_dir.as_ref().to_path_buf();
        let provenance_path = release_dir.join(PROVENANCE_FILE);
        let provenance_content = fs::read_to_string(&provenance_path).ok();
        let artifacts_object = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "artifacts"))
            .unwrap_or_default();
        let image_inputs = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "image_inputs"))
            .unwrap_or_default();
        let alpha_runtime = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "alpha_runtime"))
            .unwrap_or_default();

        let rootfs = RootfsManifestProjection::collect(
            &release_dir,
            &artifacts_object,
            &image_inputs,
            &alpha_runtime,
        );
        let gates = GATE_SPECS
            .iter()
            .map(|spec| GateProjection::collect(&release_dir, &artifacts_object, spec))
            .collect::<Vec<_>>();
        let qemu = QemuGateProjection::from_gate(
            gates
                .iter()
                .find(|gate| gate.name == "qemu_runtime_smoke")
                .expect("qemu gate spec exists"),
        );
        let blockers = collect_blockers(provenance_content.is_some(), &rootfs, &qemu, &gates);

        Self {
            schema_version: GATE_STATUS_PANEL_SCHEMA_VERSION,
            release_dir: release_dir.display().to_string(),
            provenance_path: provenance_path.display().to_string(),
            provenance_present: provenance_content.is_some(),
            rootfs,
            qemu,
            gates,
            blockers,
        }
    }

    pub fn render(&self) -> String {
        let passed_count = self
            .gates
            .iter()
            .filter(|gate| gate.status == "passed")
            .count();
        let missing_count = self
            .gates
            .iter()
            .filter(|gate| gate.status == "missing")
            .count();
        let degraded_count = self
            .gates
            .iter()
            .filter(|gate| gate.status != "passed")
            .count();
        let mut lines = vec![
            "TUI Gate Status".to_string(),
            format!(
                "gate_status_panel schema={} read_only=true projection_controller_only=true gate_execution_authority=false qemu_execution_in_tui=false rootfs_validation_in_tui=false replay_execution_in_tui=false artifact_generation_in_tui=false promotion_blocker_link=\"promotion.blockers.show\"",
                self.schema_version
            ),
            format!(
                "gate_summary status={} total={} passed={} degraded={} missing={} blocker_count={} provenance_present={} provenance_path=\"{}\" missing_gate_artifact={} stale_gate_artifact={}",
                if self.blockers.is_empty() { "passed" } else { "blocked" },
                self.gates.len(),
                passed_count,
                degraded_count,
                missing_count,
                self.blockers.len(),
                self.provenance_present,
                safe_text(&self.provenance_path),
                missing_count > 0,
                self.gates.iter().any(|gate| gate.stale)
            ),
            format!(
                "qemu_gate status={} observed_all_markers={} tui_console_ready={} runtime_artifacts_ok={} runtime_manifest_marker=\"{}\" qemu_path=\"{}\" log_path=\"{}\" safe_next_command=\"{}\"",
                safe_text(&self.qemu.status),
                self.qemu.observed_all_markers,
                self.qemu.tui_console_ready,
                self.qemu.runtime_artifacts_ok,
                safe_text(&self.qemu.runtime_manifest_marker),
                safe_text(&self.qemu.qemu_path),
                safe_text(&self.qemu.log_path),
                GATE_SPECS[0].command
            ),
            format!(
                "rootfs_manifest status={} schema=\"{}\" path=\"{}\" recorded_sha256=\"{}\" runtime_manifest_sha256=\"{}\" artifact_count={} required_artifact_count={} missing_runtime_artifact_ids=\"{}\" failed_runtime_artifact_ids=\"{}\" hash_tied_to_release_provenance={}",
                safe_text(&self.rootfs.status),
                safe_text(&self.rootfs.schema),
                safe_text(&self.rootfs.path),
                safe_text(&self.rootfs.recorded_sha256),
                safe_text(&self.rootfs.runtime_manifest_sha256),
                self.rootfs.runtime_artifact_ids.len(),
                self.rootfs.required_runtime_artifact_ids.len(),
                safe_join(&self.rootfs.missing_runtime_artifact_ids),
                safe_join(&self.rootfs.failed_runtime_artifact_ids),
                self.rootfs.hash_tied_to_release_provenance
            ),
            format!(
                "runtime_markers required=\"{}\" observed=\"{}\" tui_marker=\"AGENTOS_TUI_CONSOLE_READY\" tui_marker_observed={}",
                safe_text(&REQUIRED_RUNTIME_MARKERS.join("|")),
                safe_join(&self.qemu.observed_marker_names),
                self.qemu.tui_console_ready
            ),
            "gate_invariants script_execution_in_tui=false qemu_boot_in_tui=false rootfs_validation_execution_in_tui=false replay_execution_in_tui=false release_artifact_mutation_in_tui=false hashes_paths_and_status_only=true".to_string(),
        ];
        lines.extend(self.gates.iter().map(GateProjection::render));
        if self.blockers.is_empty() {
            lines.push("gate_blocker id=none severity=none status=clear evidence_path=\"-\" safe_next_command=\"release.provenance.show\" message=\"all gate artifacts are present and passed\"".to_string());
        } else {
            lines.extend(self.blockers.iter().map(GateBlocker::render));
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsManifestProjection {
    pub status: String,
    pub schema: String,
    pub path: String,
    pub recorded_sha256: String,
    pub runtime_manifest_sha256: String,
    pub runtime_artifact_ids: Vec<String>,
    pub required_runtime_artifact_ids: Vec<String>,
    pub missing_runtime_artifact_ids: Vec<String>,
    pub failed_runtime_artifact_ids: Vec<String>,
    pub hash_tied_to_release_provenance: bool,
}

impl RootfsManifestProjection {
    fn collect(
        release_dir: &Path,
        artifacts_object: &str,
        image_inputs: &str,
        alpha_runtime: &str,
    ) -> Self {
        let artifact =
            json_object_section(artifacts_object, "rootfs_runtime_manifest").unwrap_or_default();
        let path = json_string(&artifact, "path")
            .or_else(|| json_string(image_inputs, "rootfs_runtime_manifest"))
            .unwrap_or_else(|| {
                "image/out/agentos-alpha-rootfs/usr/lib/agentos/release/rootfs-runtime-manifest.json"
                    .to_string()
            });
        let recorded_sha256 =
            json_string(&artifact, "sha256").unwrap_or_else(|| "missing".to_string());
        let resolved = resolve_artifact_path(release_dir, &path);
        let manifest_content = resolved
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok());
        let runtime_manifest_sha256 = json_string(image_inputs, "rootfs_runtime_manifest_sha256")
            .or_else(|| json_string(alpha_runtime, "rootfs_runtime_manifest_sha256"))
            .unwrap_or_else(|| recorded_sha256.clone());
        let runtime_artifact_ids = manifest_content
            .as_deref()
            .map(|content| json_string_array(content, "runtime_artifact_ids"))
            .filter(|ids| !ids.is_empty())
            .or_else(|| Some(json_string_array(alpha_runtime, "runtime_artifact_ids")))
            .unwrap_or_default();
        let mut required_runtime_artifact_ids =
            json_string_array(alpha_runtime, "required_runtime_artifact_ids")
                .into_iter()
                .chain(required_runtime_artifact_ids())
                .collect::<Vec<_>>();
        required_runtime_artifact_ids.sort();
        required_runtime_artifact_ids.dedup();
        let missing_runtime_artifact_ids =
            json_string_array(alpha_runtime, "missing_runtime_artifact_ids");
        let failed_runtime_artifact_ids =
            json_string_array(alpha_runtime, "failed_runtime_artifact_ids");
        let schema = manifest_content
            .as_deref()
            .and_then(|content| json_string(content, "schema"))
            .or_else(|| json_string(image_inputs, "rootfs_runtime_manifest_schema"))
            .unwrap_or_else(|| "missing".to_string());
        let present =
            manifest_content.is_some() || resolved.as_ref().is_some_and(|path| path.exists());
        let hash_tied_to_release_provenance = recorded_sha256 != "missing"
            && runtime_manifest_sha256 != "missing"
            && recorded_sha256 == runtime_manifest_sha256;
        let status = if !present {
            "missing"
        } else if !missing_runtime_artifact_ids.is_empty()
            || !failed_runtime_artifact_ids.is_empty()
        {
            "blocked"
        } else if hash_tied_to_release_provenance {
            "passed"
        } else {
            "degraded"
        }
        .to_string();
        Self {
            status,
            schema,
            path,
            recorded_sha256,
            runtime_manifest_sha256,
            runtime_artifact_ids,
            required_runtime_artifact_ids,
            missing_runtime_artifact_ids,
            failed_runtime_artifact_ids,
            hash_tied_to_release_provenance,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QemuGateProjection {
    pub status: String,
    pub observed_all_markers: bool,
    pub tui_console_ready: bool,
    pub runtime_artifacts_ok: bool,
    pub runtime_manifest_marker: String,
    pub observed_marker_names: Vec<String>,
    pub qemu_path: String,
    pub log_path: String,
}

impl QemuGateProjection {
    fn from_gate(gate: &GateProjection) -> Self {
        let content = gate.content.as_deref().unwrap_or_default();
        let observed_markers = json_object_section(content, "observed_markers").unwrap_or_default();
        let observed_marker_names = REQUIRED_RUNTIME_MARKERS
            .iter()
            .filter(|marker| json_bool(&observed_markers, marker).unwrap_or(false))
            .map(|marker| (*marker).to_string())
            .collect::<Vec<_>>();
        let observed_all_markers = json_bool(content, "observed_all_markers").unwrap_or(false);
        let tui_console_ready =
            json_bool(&observed_markers, "AGENTOS_TUI_CONSOLE_READY").unwrap_or(false);
        let runtime_artifacts_ok =
            json_bool(&observed_markers, "AGENTOS_RUNTIME_ARTIFACTS_OK").unwrap_or(false);
        let status = if gate.status == "passed"
            && observed_all_markers
            && tui_console_ready
            && runtime_artifacts_ok
        {
            "passed".to_string()
        } else if gate.present {
            "blocked".to_string()
        } else {
            gate.status.clone()
        };
        Self {
            status,
            observed_all_markers,
            tui_console_ready,
            runtime_artifacts_ok,
            runtime_manifest_marker: json_string(content, "runtime_manifest_marker")
                .unwrap_or_else(|| "-".to_string()),
            observed_marker_names,
            qemu_path: json_string(content, "qemu_path").unwrap_or_else(|| "-".to_string()),
            log_path: json_string(content, "log_path").unwrap_or_else(|| "-".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateProjection {
    pub name: String,
    pub status: String,
    pub path: String,
    pub present: bool,
    pub required: bool,
    pub recorded_sha256: String,
    pub source_status: String,
    pub safe_next_command: &'static str,
    pub stale: bool,
    content: Option<String>,
}

impl GateProjection {
    fn collect(release_dir: &Path, artifacts_object: &str, spec: &GateSpec) -> Self {
        let artifact = json_object_section(artifacts_object, spec.name).unwrap_or_default();
        let path = json_string(&artifact, "path").unwrap_or_else(|| spec.default_path.to_string());
        let recorded_sha256 =
            json_string(&artifact, "sha256").unwrap_or_else(|| "missing".to_string());
        let required = json_bool(&artifact, "required").unwrap_or(true);
        let resolved = resolve_artifact_path(release_dir, &path);
        let content = resolved
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok());
        let present = content.is_some();
        let stale = present && recorded_sha256 == "missing";
        let source_status = source_status(content.as_deref(), spec.status_kind);
        let status = if stale {
            "degraded"
        } else {
            gate_status(present, &source_status, spec.status_kind)
        }
        .to_string();
        Self {
            name: spec.name.to_string(),
            status,
            path,
            present,
            required,
            recorded_sha256,
            source_status,
            safe_next_command: spec.command,
            stale,
            content,
        }
    }

    fn render(&self) -> String {
        format!(
            "gate name={} status={} source_status={} present={} required={} stale={} path=\"{}\" recorded_sha256=\"{}\" safe_next_command=\"{}\"",
            safe_text(&self.name),
            safe_text(&self.status),
            safe_text(&self.source_status),
            self.present,
            self.required,
            self.stale,
            safe_text(&self.path),
            safe_text(&self.recorded_sha256),
            safe_text(self.safe_next_command)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateBlocker {
    pub id: String,
    pub severity: String,
    pub status: String,
    pub evidence_path: String,
    pub safe_next_command: String,
    pub message: String,
}

impl GateBlocker {
    fn new(
        id: impl Into<String>,
        status: impl Into<String>,
        evidence_path: impl Into<String>,
        safe_next_command: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let status = status.into();
        Self {
            message: blocker_message(&id, &status),
            id,
            severity: "blocking".to_string(),
            status,
            evidence_path: evidence_path.into(),
            safe_next_command: safe_next_command.into(),
        }
    }

    fn render(&self) -> String {
        format!(
            "gate_blocker id=\"{}\" severity={} status={} evidence_path=\"{}\" safe_next_command=\"{}\" message=\"{}\"",
            safe_text(&self.id),
            safe_text(&self.severity),
            safe_text(&self.status),
            safe_text(&self.evidence_path),
            safe_text(&self.safe_next_command),
            safe_text(&self.message)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GateSpec {
    name: &'static str,
    default_path: &'static str,
    command: &'static str,
    status_kind: GateStatusKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateStatusKind {
    QemuBoot,
    StatusField,
    ResultField,
}

fn collect_blockers(
    provenance_present: bool,
    rootfs: &RootfsManifestProjection,
    qemu: &QemuGateProjection,
    gates: &[GateProjection],
) -> Vec<GateBlocker> {
    let mut blockers = Vec::new();
    if !provenance_present {
        blockers.push(GateBlocker::new(
            "release-provenance-missing",
            "missing-evidence",
            ".workflow/artifacts/release/provenance.json",
            "release.provenance.show",
        ));
    }
    if rootfs.status != "passed" {
        blockers.push(GateBlocker::new(
            "rootfs-runtime-manifest-not-passed",
            &rootfs.status,
            &rootfs.path,
            "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/validate-alpha-rootfs.ps1",
        ));
    }
    if !qemu.tui_console_ready {
        blockers.push(GateBlocker::new(
            "qemu-tui-console-marker-missing",
            "missing-marker",
            ".workflow/artifacts/boot/boot-smoke-result.json",
            GATE_SPECS[0].command,
        ));
    }
    blockers.extend(
        gates
            .iter()
            .filter(|gate| gate.status != "passed")
            .map(|gate| {
                GateBlocker::new(
                    format!("gate-not-passed:{}", gate.name),
                    gate.status.clone(),
                    gate.path.clone(),
                    gate.safe_next_command,
                )
            }),
    );
    blockers.sort_by(|left, right| left.id.cmp(&right.id));
    blockers
}

fn source_status(content: Option<&str>, status_kind: GateStatusKind) -> String {
    let Some(content) = content else {
        return "missing".to_string();
    };
    match status_kind {
        GateStatusKind::QemuBoot => json_string(content, "status").unwrap_or_else(|| {
            if json_bool(content, "observed_all_markers").unwrap_or(false) {
                "completed".to_string()
            } else {
                "unknown".to_string()
            }
        }),
        GateStatusKind::StatusField => {
            json_string(content, "status").unwrap_or_else(|| "unknown".to_string())
        }
        GateStatusKind::ResultField => json_string(content, "result")
            .or_else(|| json_string(content, "status"))
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

fn gate_status(present: bool, source_status: &str, status_kind: GateStatusKind) -> &'static str {
    if !present {
        return "missing";
    }
    match status_kind {
        GateStatusKind::QemuBoot => {
            if source_status == "completed" {
                "passed"
            } else {
                "blocked"
            }
        }
        GateStatusKind::StatusField | GateStatusKind::ResultField => {
            if source_status == "passed" {
                "passed"
            } else {
                "blocked"
            }
        }
    }
}

fn blocker_message(id: &str, status: &str) -> String {
    match status {
        "missing" | "missing-evidence" => format!("required gate evidence is missing: {id}"),
        "missing-marker" => format!("required boot marker is missing: {id}"),
        "blocked" => format!("required gate is not passed: {id}"),
        "degraded" => format!("gate evidence is degraded: {id}"),
        other => format!("gate status is {other}: {id}"),
    }
}

fn required_runtime_artifact_ids() -> Vec<String> {
    [
        "policy.pack",
        "tools.semantic",
        "operator.commands",
        "ecosystem.registry_snapshot",
        "ecosystem.core_policy",
        "ecosystem.workflow_service_recovery",
        "model_broker.config",
        "tui.config",
        "state.runs",
        "state.audit",
        "state.rollback",
        "state.memory",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect()
}

fn resolve_artifact_path(release_dir: &Path, value: &str) -> Option<PathBuf> {
    if value.trim().is_empty() || value == "-" {
        return None;
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else {
        let release_relative = release_dir.join(&path);
        if release_relative.exists() || path.components().count() == 1 {
            Some(release_relative)
        } else {
            Some(resolve_repo_path(value))
        }
    }
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
