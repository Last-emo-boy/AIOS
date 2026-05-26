use std::path::Path;

use crate::api::escape_json;
use crate::audit::redact_summary;

use super::release_provenance_panel::{DEFAULT_RELEASE_ARTIFACT_DIR, ReleaseProvenancePanel};

pub const PROMOTION_BLOCKER_PANEL_SCHEMA_VERSION: &str = "agentos.tui-promotion-blocker-panel.v1";

const PROMOTION_BLOCKER_CATEGORIES: &[(&str, &str)] = &[
    ("tests", "tests"),
    ("boot-smoke", "boot smoke"),
    ("replay", "replay"),
    ("signing", "signing"),
    ("provenance", "provenance"),
    ("ecosystem-readiness", "ecosystem readiness"),
    ("other", "other"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionBlockerPanel {
    pub schema_version: &'static str,
    pub release_dir: String,
    pub promotion_status: String,
    pub blockers: Vec<PromotionBlockerItem>,
    pub skipped_required_gates: Vec<PromotionBlockerItem>,
    pub warnings: Vec<String>,
    pub evidence_source: String,
}

impl PromotionBlockerPanel {
    pub fn collect() -> Self {
        Self::from_provenance(ReleaseProvenancePanel::collect())
    }

    pub fn collect_from_dir(release_dir: impl AsRef<Path>) -> Self {
        Self::from_provenance(ReleaseProvenancePanel::collect_from_dir(release_dir))
    }

    pub fn from_provenance(provenance: ReleaseProvenancePanel) -> Self {
        let mut blockers = provenance
            .promotion_blockers
            .iter()
            .map(|blocker| PromotionBlockerItem::from_blocker(blocker))
            .collect::<Vec<_>>();

        let mut skipped_required_gates = provenance
            .gate_statuses
            .iter()
            .filter(|gate| gate.status == "skipped")
            .map(|gate| {
                PromotionBlockerItem::from_skipped_gate(
                    &gate.name,
                    &gate.command,
                    &gate.evidence_path,
                )
            })
            .collect::<Vec<_>>();
        for skipped in &skipped_required_gates {
            if !blockers
                .iter()
                .any(|blocker| blocker.id == skipped.id && blocker.category == skipped.category)
            {
                blockers.push(skipped.clone());
            }
        }
        blockers.sort_by(|left, right| {
            left.category
                .cmp(&right.category)
                .then_with(|| left.id.cmp(&right.id))
        });
        skipped_required_gates.sort_by(|left, right| left.id.cmp(&right.id));

        Self {
            schema_version: PROMOTION_BLOCKER_PANEL_SCHEMA_VERSION,
            release_dir: provenance.release_dir,
            promotion_status: provenance.promotion_status,
            blockers,
            skipped_required_gates,
            warnings: provenance.promotion_warnings,
            evidence_source: provenance.provenance_path,
        }
    }

    pub fn render(&self) -> String {
        let mut lines = vec![
            "TUI Promotion Blockers".to_string(),
            format!(
                "promotion_blocker_panel schema={} read_only=true projection_controller_only=true release_authority=false blocker_override_allowed=false clear_blocker_allowed=false direct_sign=false direct_promote=false artifact_generation_in_tui=false provenance_mutation_in_tui=false source=\"{}\"",
                self.schema_version,
                safe_text(&self.evidence_source)
            ),
            format!(
                "promotion_summary status={} blocker_count={} skipped_required_gate_count={} warning_count={} safe_refresh=\"{}\" provenance_command=\"{}\"",
                safe_text(&self.promotion_status),
                self.blockers.len(),
                self.skipped_required_gates.len(),
                self.warnings.len(),
                "release.provenance.show",
                "release.provenance.show"
            ),
            format!(
                "warnings values=\"{}\" dirty_worktree_warning={} operator_can_dismiss=false",
                safe_join(&self.warnings),
                self.warnings.iter().any(|warning| warning == "dirty-worktree")
            ),
            "promotion_invariants blockers_source=release-provenance skipped_required_gates_are_blockers=true tui_can_clear_blockers=false tui_can_mark_promoted=false mutation_path=\"scripts/build-release.ps1 or CI gate only\"".to_string(),
        ];
        lines.extend(PROMOTION_BLOCKER_CATEGORIES.iter().map(|(category, label)| {
            let category_blockers = self
                .blockers
                .iter()
                .filter(|blocker| blocker.category == *category)
                .collect::<Vec<_>>();
            let skipped_required_gate_count = category_blockers
                .iter()
                .filter(|blocker| blocker.status == "skipped-required-gate")
                .count();
            let blocking_count = category_blockers
                .iter()
                .filter(|blocker| blocker.severity == "blocking")
                .count();
            let warning_count = category_blockers
                .iter()
                .filter(|blocker| blocker.severity == "warning")
                .count();
            format!(
                "blocker_group category={} label=\"{}\" count={} skipped_required_gate_count={} blocking_count={} warning_count={}",
                safe_text(category),
                safe_text(label),
                category_blockers.len(),
                skipped_required_gate_count,
                blocking_count,
                warning_count
            )
        }));
        if self.blockers.is_empty() {
            lines.push("blocker id=none category=none severity=none status=clear evidence_path=\"-\" safe_next_command=\"release.provenance.show\" message=\"no promotion blockers in current provenance\"".to_string());
        } else {
            lines.extend(self.blockers.iter().map(PromotionBlockerItem::render));
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionBlockerItem {
    pub id: String,
    pub category: String,
    pub severity: String,
    pub status: String,
    pub evidence_path: String,
    pub safe_next_command: String,
    pub message: String,
}

impl PromotionBlockerItem {
    fn from_blocker(blocker: &str) -> Self {
        let category = blocker_category(blocker);
        Self {
            id: blocker.to_string(),
            severity: severity_for_category(category).to_string(),
            status: status_for_blocker(blocker).to_string(),
            evidence_path: evidence_path_for_blocker(blocker).to_string(),
            safe_next_command: next_command_for_blocker(blocker).to_string(),
            message: message_for_blocker(blocker).to_string(),
            category: category.to_string(),
        }
    }

    fn from_skipped_gate(name: &str, command: &str, evidence_path: &str) -> Self {
        let id = format!("required-gate-skipped:{}", normalize_gate_name(name));
        let safe_command = if command.trim().is_empty() || command == "-" {
            next_command_for_blocker(&id).to_string()
        } else {
            command.to_string()
        };
        let evidence_path = if evidence_path.trim().is_empty() || evidence_path == "-" {
            DEFAULT_RELEASE_ARTIFACT_DIR
        } else {
            evidence_path
        };
        Self {
            id,
            category: blocker_category(name).to_string(),
            severity: "blocking".to_string(),
            status: "skipped-required-gate".to_string(),
            evidence_path: evidence_path.to_string(),
            safe_next_command: safe_command,
            message: format!("required release gate was skipped: {name}"),
        }
    }

    fn render(&self) -> String {
        format!(
            "blocker id=\"{}\" category={} severity={} status={} evidence_path=\"{}\" safe_next_command=\"{}\" message=\"{}\"",
            safe_text(&self.id),
            safe_text(&self.category),
            safe_text(&self.severity),
            safe_text(&self.status),
            safe_text(&self.evidence_path),
            safe_text(&self.safe_next_command),
            safe_text(&self.message)
        )
    }
}

fn blocker_category(blocker: &str) -> &'static str {
    let lower = blocker.to_ascii_lowercase();
    if lower.contains("test") || lower.contains("safety") || lower.contains("agent_core") {
        "tests"
    } else if lower.contains("qemu") || lower.contains("boot") || lower.contains("rootfs") {
        "boot-smoke"
    } else if lower.contains("sign") || lower.contains("signature") || lower.contains("key") {
        "signing"
    } else if lower.contains("provenance")
        || lower.contains("sbom")
        || lower.contains("dependency")
        || lower.contains("update-metadata")
        || lower.contains("release-file")
    {
        "provenance"
    } else if lower.contains("ecosystem")
        || lower.contains("active-artifact")
        || lower.contains("registry")
        || lower.contains("compatibility")
    {
        "ecosystem-readiness"
    } else if lower.contains("replay") || lower.contains("runbook") {
        "replay"
    } else {
        "other"
    }
}

fn severity_for_category(category: &str) -> &'static str {
    match category {
        "other" => "warning",
        _ => "blocking",
    }
}

fn status_for_blocker(blocker: &str) -> &'static str {
    let lower = blocker.to_ascii_lowercase();
    if lower.contains("skipped") {
        "skipped-required-gate"
    } else if lower.contains("missing") {
        "missing-evidence"
    } else if lower.contains("failed") {
        "failed-gate"
    } else {
        "blocked"
    }
}

fn evidence_path_for_blocker(blocker: &str) -> &'static str {
    let lower = blocker.to_ascii_lowercase();
    if lower.contains("qemu") || lower.contains("boot") {
        ".workflow/artifacts/boot/boot-smoke-result.json"
    } else if lower.contains("tui-replay") {
        ".workflow/artifacts/tui-replay/result.json"
    } else if lower.contains("ecosystem-replay")
        || lower.contains("ecosystem")
        || lower.contains("active-artifact")
        || lower.contains("registry")
        || lower.contains("compatibility")
    {
        ".workflow/artifacts/ecosystem-replay/result.json"
    } else if lower.contains("functional") {
        ".workflow/artifacts/functional-replay/result.json"
    } else if lower.contains("runbook") {
        ".workflow/artifacts/production-runbook-smoke/result.json"
    } else if lower.contains("signature") || lower.contains("signing") || lower.contains("key") {
        ".workflow/artifacts/release"
    } else if lower.contains("rootfs") {
        "image/out/agentos-alpha-rootfs.validation.json"
    } else {
        ".workflow/artifacts/release/provenance.json"
    }
}

fn next_command_for_blocker(blocker: &str) -> &'static str {
    let lower = blocker.to_ascii_lowercase();
    if lower.contains("test") || lower.contains("safety") || lower.contains("agent_core") {
        "cargo test -p agentd"
    } else if lower.contains("qemu") || lower.contains("boot") {
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/boot-smoke-test.ps1 -QemuPath E:\\qemu\\qemu-system-x86_64.exe -TimeoutSeconds 120"
    } else if lower.contains("tui-replay") {
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/tui-replay.ps1"
    } else if lower.contains("ecosystem-replay")
        || lower.contains("ecosystem")
        || lower.contains("active-artifact")
        || lower.contains("registry")
        || lower.contains("compatibility")
    {
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/ecosystem-replay.ps1"
    } else if lower.contains("functional") {
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/functional-capability-replay.ps1"
    } else if lower.contains("runbook") {
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/production-runbook-smoke.ps1"
    } else if lower.contains("signature") || lower.contains("signing") || lower.contains("key") {
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1"
    } else {
        "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1"
    }
}

fn message_for_blocker(blocker: &str) -> String {
    match status_for_blocker(blocker) {
        "skipped-required-gate" => format!("required release gate is skipped: {blocker}"),
        "missing-evidence" => format!("required release evidence is missing: {blocker}"),
        "failed-gate" => format!("release gate failed: {blocker}"),
        _ => format!("promotion is blocked by release provenance: {blocker}"),
    }
}

fn normalize_gate_name(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
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
