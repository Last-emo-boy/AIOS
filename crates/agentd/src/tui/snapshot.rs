use std::fs;
use std::path::PathBuf;

use crate::agent_core::run_loop::RunProjection;
use crate::api::escape_json;
use crate::audit::{AuditJournal, RuntimeAuditProjection};
use crate::lifecycle::Agentd;
use crate::operator_projection::OperatorProjection;
use crate::runtime_contracts::stable_contract_hash;
use crate::support_bundle::SupportBundleProjection;

use super::render::binding_for_step;
use super::runtime::TuiRuntimePaths;

pub const PROJECTION_SNAPSHOT_SCHEMA_VERSION: &str = "agentos.tui-projection-snapshot.v1";

const RELEASE_EVIDENCE_FILES: &[&str] = &[
    ".workflow/artifacts/release/provenance.json",
    ".workflow/artifacts/release/dependency-inventory.json",
    ".workflow/artifacts/release/sbom.json",
    ".workflow/artifacts/release/update-metadata.json",
    ".workflow/artifacts/boot/boot-smoke-result.json",
    ".workflow/artifacts/tui-replay/result.json",
    ".workflow/artifacts/ecosystem-replay/result.json",
    "image/out/agentos-alpha-rootfs.validation.json",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionSnapshot {
    pub schema_version: &'static str,
    pub immutable_render_input: bool,
    pub source_of_truth: bool,
    pub latest_run_id: Option<String>,
    pub snapshot_hash: String,
    pub runs: ProjectionSourceSnapshot,
    pub audit: ProjectionSourceSnapshot,
    pub approvals: ProjectionSourceSnapshot,
    pub recovery: ProjectionSourceSnapshot,
    pub support: ProjectionSourceSnapshot,
    pub ecosystem: ProjectionSourceSnapshot,
    pub release: ProjectionSourceSnapshot,
}

impl ProjectionSnapshot {
    pub fn collect(
        agentd: &Agentd,
        journal: &AuditJournal,
        paths: &TuiRuntimePaths,
        run_projection: Result<Option<RunProjection>, String>,
        audit_projection: Result<Option<RuntimeAuditProjection>, String>,
    ) -> Self {
        let runs = run_source(paths, &run_projection);
        let latest_run_id = run_projection
            .as_ref()
            .ok()
            .and_then(|run| run.as_ref())
            .map(|run| run.run_id.clone());
        let audit = audit_source(journal, &audit_projection);
        let approvals = approvals_source(&run_projection, &audit_projection);
        let recovery = recovery_source(&run_projection, &audit_projection);
        let support = support_source(journal, latest_run_id.as_deref().unwrap_or("no-run"));
        let ecosystem = ecosystem_source(agentd, journal, latest_run_id.as_deref());
        let release = release_source();
        let snapshot_hash = snapshot_hash([
            &runs, &audit, &approvals, &recovery, &support, &ecosystem, &release,
        ]);
        Self {
            schema_version: PROJECTION_SNAPSHOT_SCHEMA_VERSION,
            immutable_render_input: true,
            source_of_truth: false,
            latest_run_id,
            snapshot_hash,
            runs,
            audit,
            approvals,
            recovery,
            support,
            ecosystem,
            release,
        }
    }

    pub fn has_degraded_sources(&self) -> bool {
        !self.degraded_sources().is_empty()
    }

    pub fn degraded_sources(&self) -> Vec<&ProjectionSourceSnapshot> {
        [
            &self.runs,
            &self.audit,
            &self.approvals,
            &self.recovery,
            &self.support,
            &self.ecosystem,
            &self.release,
        ]
        .into_iter()
        .filter(|source| source.degraded)
        .collect()
    }

    pub fn to_cli_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "Projection Snapshot schema={} immutable_render_input={} source_of_truth={} latest_run={} snapshot_hash={} degraded={}",
            self.schema_version,
            self.immutable_render_input,
            self.source_of_truth,
            self.latest_run_id.as_deref().unwrap_or("-"),
            self.snapshot_hash,
            self.has_degraded_sources()
        )];
        lines.extend(
            [
                &self.runs,
                &self.audit,
                &self.approvals,
                &self.recovery,
                &self.support,
                &self.ecosystem,
                &self.release,
            ]
            .into_iter()
            .map(ProjectionSourceSnapshot::to_cli_line),
        );
        lines
    }

    pub fn to_cli_text(&self) -> String {
        self.to_cli_lines().join("\n")
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":\"{}\",\"immutable_render_input\":{},\"source_of_truth\":{},\"latest_run_id\":{},\"snapshot_hash\":\"{}\",\"degraded\":{},\"runs\":{},\"audit\":{},\"approvals\":{},\"recovery\":{},\"support\":{},\"ecosystem\":{},\"release\":{}}}",
            self.schema_version,
            self.immutable_render_input,
            self.source_of_truth,
            optional_json(self.latest_run_id.as_deref()),
            escape_json(&self.snapshot_hash),
            self.has_degraded_sources(),
            self.runs.to_json(),
            self.audit.to_json(),
            self.approvals.to_json(),
            self.recovery.to_json(),
            self.support.to_json(),
            self.ecosystem.to_json(),
            self.release.to_json()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionSourceSnapshot {
    pub name: &'static str,
    pub authority: &'static str,
    pub status: String,
    pub freshness: String,
    pub source_hash: String,
    pub degraded: bool,
    pub detail: String,
}

impl ProjectionSourceSnapshot {
    fn new(
        name: &'static str,
        authority: &'static str,
        status: impl Into<String>,
        freshness: impl Into<String>,
        source_hash_input: impl AsRef<str>,
        degraded: bool,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            name,
            authority,
            status: status.into(),
            freshness: freshness.into(),
            source_hash: stable_contract_hash(source_hash_input.as_ref()),
            degraded,
            detail: detail.into(),
        }
    }

    pub fn to_cli_line(&self) -> String {
        format!(
            "{} status={} freshness={} hash={} degraded={} authority=\"{}\" detail=\"{}\"",
            self.name,
            self.status,
            self.freshness,
            self.source_hash,
            self.degraded,
            self.authority,
            escape_json(&self.detail)
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"name\":\"{}\",\"authority\":\"{}\",\"status\":\"{}\",\"freshness\":\"{}\",\"source_hash\":\"{}\",\"degraded\":{},\"detail\":\"{}\"}}",
            self.name,
            escape_json(self.authority),
            escape_json(&self.status),
            escape_json(&self.freshness),
            escape_json(&self.source_hash),
            self.degraded,
            escape_json(&self.detail)
        )
    }
}

fn run_source(
    paths: &TuiRuntimePaths,
    run_projection: &Result<Option<RunProjection>, String>,
) -> ProjectionSourceSnapshot {
    match run_projection {
        Ok(Some(run)) => ProjectionSourceSnapshot::new(
            "runs",
            "AgentCore RunStore",
            run.state.as_str(),
            "rebuilt-from-run-store",
            format!("runs:{}", run.to_json()),
            false,
            format!(
                "run={} step={} approval={} recovery={}",
                run.run_id,
                run.current_step_id.as_deref().unwrap_or("-"),
                run.approval_status.as_str(),
                run.recovery_status.as_str()
            ),
        ),
        Ok(None) => ProjectionSourceSnapshot::new(
            "runs",
            "AgentCore RunStore",
            if paths.run_store_root.is_dir() {
                "no-run"
            } else {
                "missing"
            },
            if paths.run_store_root.is_dir() {
                "empty"
            } else {
                "missing"
            },
            "runs:no-run",
            !paths.run_store_root.is_dir(),
            format!("run_store={}", paths.run_store_root.display()),
        ),
        Err(error) => ProjectionSourceSnapshot::new(
            "runs",
            "AgentCore RunStore",
            "degraded",
            "unreadable",
            format!("runs:error={error}"),
            true,
            error,
        ),
    }
}

fn audit_source(
    journal: &AuditJournal,
    audit_projection: &Result<Option<RuntimeAuditProjection>, String>,
) -> ProjectionSourceSnapshot {
    let event_lines = journal.event_lines();
    match audit_projection {
        Ok(Some(projection)) => ProjectionSourceSnapshot::new(
            "audit",
            "SecurityExecutionEngine AuditJournal",
            "present",
            "rebuilt-from-audit-journal",
            projection.to_json(),
            !projection.warnings.is_empty(),
            format!(
                "run={} events={} warnings={}",
                projection.run_id,
                projection.event_count(),
                projection.warnings.len()
            ),
        ),
        Ok(None) => match event_lines {
            Ok(lines) => ProjectionSourceSnapshot::new(
                "audit",
                "SecurityExecutionEngine AuditJournal",
                if lines.is_empty() {
                    "no-events"
                } else {
                    "no-run"
                },
                if lines.is_empty() {
                    "empty"
                } else {
                    "no-selected-run"
                },
                format!("audit:{}", lines.join("\n")),
                false,
                format!(
                    "journal={} events={}",
                    journal.path().display(),
                    lines.len()
                ),
            ),
            Err(error) => ProjectionSourceSnapshot::new(
                "audit",
                "SecurityExecutionEngine AuditJournal",
                "degraded",
                "unreadable",
                format!("audit:error={error}"),
                true,
                error.to_string(),
            ),
        },
        Err(error) => ProjectionSourceSnapshot::new(
            "audit",
            "SecurityExecutionEngine AuditJournal",
            "degraded",
            "unreadable",
            format!("audit:error={error}"),
            true,
            error,
        ),
    }
}

fn approvals_source(
    run_projection: &Result<Option<RunProjection>, String>,
    audit_projection: &Result<Option<RuntimeAuditProjection>, String>,
) -> ProjectionSourceSnapshot {
    let Ok(Some(run)) = run_projection else {
        return ProjectionSourceSnapshot::new(
            "approvals",
            "AgentCore ApprovalToken + SecurityExecutionEngine AuditJournal",
            "no-run",
            "missing-run",
            "approvals:no-run",
            false,
            "no run selected",
        );
    };
    let status = approval_status(run.approval_status.as_str());
    let step = run.current_step_id.as_deref().unwrap_or("-");
    let binding_present = audit_projection
        .as_ref()
        .ok()
        .and_then(|projection| projection.as_ref())
        .and_then(|projection| binding_for_step(projection, step))
        .is_some();
    let degraded = status == "pending" && !binding_present;
    ProjectionSourceSnapshot::new(
        "approvals",
        "AgentCore ApprovalToken + SecurityExecutionEngine AuditJournal",
        status,
        if binding_present {
            "exact-binding"
        } else {
            "binding-unavailable"
        },
        format!(
            "approvals:{}:{}:{}:{}",
            run.run_id,
            step,
            run.approval_status.as_str(),
            binding_present
        ),
        degraded,
        format!(
            "run={} step={} approval={} exact_binding={}",
            run.run_id,
            step,
            run.approval_status.as_str(),
            binding_present
        ),
    )
}

fn recovery_source(
    run_projection: &Result<Option<RunProjection>, String>,
    audit_projection: &Result<Option<RuntimeAuditProjection>, String>,
) -> ProjectionSourceSnapshot {
    let Ok(Some(run)) = run_projection else {
        return ProjectionSourceSnapshot::new(
            "recovery",
            "AgentCore RunStore + SecurityExecutionEngine AuditJournal",
            "no-run",
            "missing-run",
            "recovery:no-run",
            false,
            "no run selected",
        );
    };
    let rollback_steps = audit_projection
        .as_ref()
        .ok()
        .and_then(|projection| projection.as_ref())
        .map(|projection| {
            projection
                .steps
                .iter()
                .filter(|step| step.effect_state == "rollback-pending")
                .map(|step| step.step_id.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let needs_human = matches!(
        run.state.as_str(),
        "AwaitingApproval" | "Suspended" | "RollbackPending" | "FailedClosed"
    );
    let degraded = needs_human || !rollback_steps.is_empty();
    ProjectionSourceSnapshot::new(
        "recovery",
        "AgentCore RunStore + SecurityExecutionEngine AuditJournal",
        run.recovery_status.as_str(),
        if degraded {
            "operator-attention"
        } else {
            "rebuilt-from-run-store+audit"
        },
        format!(
            "recovery:{}:{}:{}:{}",
            run.run_id,
            run.state.as_str(),
            run.recovery_status.as_str(),
            rollback_steps.join("|")
        ),
        degraded,
        format!(
            "run={} state={} rollback_pending={} human_review={}",
            run.run_id,
            run.state.as_str(),
            !rollback_steps.is_empty() || run.state.as_str() == "RollbackPending",
            needs_human
        ),
    )
}

fn support_source(journal: &AuditJournal, run_id: &str) -> ProjectionSourceSnapshot {
    match SupportBundleProjection::from_journal(
        journal,
        format!("snapshot-support-{run_id}"),
        vec![run_id],
    ) {
        Ok(projection) => {
            let status = projection.runtime.loop_status.to_string();
            let degraded = matches!(projection.runtime.loop_status, "needs-reconciliation")
                || projection
                    .ecosystem
                    .offline_baseline_status
                    .starts_with("degraded");
            ProjectionSourceSnapshot::new(
                "support",
                "support_bundle redacted projection",
                status,
                "rebuilt-from-audit-journal",
                projection.to_json(),
                degraded,
                format!(
                    "audit_excerpt_count={} ecosystem_offline={} redaction={}",
                    projection.audit_excerpt_count,
                    projection.ecosystem.offline_baseline_status,
                    projection.runtime.redaction_status
                ),
            )
        }
        Err(error) => ProjectionSourceSnapshot::new(
            "support",
            "support_bundle redacted projection",
            "degraded",
            "unreadable",
            format!("support:error={error}"),
            true,
            error.to_string(),
        ),
    }
}

fn ecosystem_source(
    agentd: &Agentd,
    journal: &AuditJournal,
    run_id: Option<&str>,
) -> ProjectionSourceSnapshot {
    match OperatorProjection::collect(agentd, Some(journal), run_id) {
        Ok(projection) => {
            let ecosystem = projection.ecosystem;
            let degraded = ecosystem.local_registry_status != "present"
                || ecosystem.active_set_status != "present"
                || ecosystem.network_required;
            ProjectionSourceSnapshot::new(
                "ecosystem",
                "agent_core::ecosystem projection",
                ecosystem.activation_status,
                if degraded {
                    "degraded-source-visible"
                } else {
                    "local-pinned"
                },
                format!(
                    "ecosystem:{}:{}:{}:{}:{}",
                    ecosystem.registry_snapshot_digest.as_deref().unwrap_or("-"),
                    ecosystem.registry_artifact_count,
                    ecosystem.active_set_status,
                    ecosystem.lockfile_hash.as_deref().unwrap_or("-"),
                    ecosystem.network_required
                ),
                degraded,
                format!(
                    "registry_status={} artifacts={} active_set_status={} resolver_owner={} activation_authority={}",
                    ecosystem.local_registry_status,
                    ecosystem.registry_artifact_count,
                    ecosystem.active_set_status,
                    ecosystem.resolver_owner,
                    ecosystem.activation_authority
                ),
            )
        }
        Err(error) => ProjectionSourceSnapshot::new(
            "ecosystem",
            "agent_core::ecosystem projection",
            "degraded",
            "unreadable",
            format!("ecosystem:error={error}"),
            true,
            error.to_string(),
        ),
    }
}

fn release_source() -> ProjectionSourceSnapshot {
    let mut present = Vec::new();
    let mut missing = Vec::new();
    let mut hash_input = String::new();
    for relative in RELEASE_EVIDENCE_FILES {
        let path = resolve_repo_path(relative);
        match fs::read_to_string(&path) {
            Ok(content) => {
                present.push(*relative);
                hash_input.push_str(relative);
                hash_input.push('=');
                hash_input.push_str(&stable_contract_hash(&content));
                hash_input.push('\n');
            }
            Err(_) => {
                missing.push(*relative);
                hash_input.push_str(relative);
                hash_input.push_str("=missing\n");
            }
        }
    }
    let status = if present.is_empty() {
        "missing"
    } else if missing.is_empty() {
        "present"
    } else {
        "partial"
    };
    ProjectionSourceSnapshot::new(
        "release",
        "local release evidence artifacts",
        status,
        if missing.is_empty() {
            "content-hash-bound"
        } else {
            "degraded-missing-evidence"
        },
        hash_input,
        !missing.is_empty(),
        format!("present={} missing={}", present.len(), missing.len()),
    )
}

fn approval_status(status: &str) -> &'static str {
    match status {
        "Pending" => "pending",
        "Denied" => "denied",
        "Expired" => "expired",
        "Granted" => "granted",
        _ => "none",
    }
}

fn snapshot_hash<const N: usize>(sources: [&ProjectionSourceSnapshot; N]) -> String {
    let mut input = format!("{PROJECTION_SNAPSHOT_SCHEMA_VERSION}\n");
    for source in sources {
        input.push_str(source.name);
        input.push('=');
        input.push_str(&source.source_hash);
        input.push(':');
        input.push_str(&source.status);
        input.push(':');
        input.push_str(&source.freshness);
        input.push(':');
        input.push_str(if source.degraded { "degraded" } else { "ok" });
        input.push('\n');
    }
    stable_contract_hash(&input)
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

fn optional_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}
