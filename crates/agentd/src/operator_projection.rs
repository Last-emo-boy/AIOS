use std::io;

use crate::api::{escape_json, RiskClass};
use crate::audit::{redact_summary, AuditJournal, RuntimeAuditProjection};
use crate::lifecycle::{Agentd, HealthReport, LifecycleState};
use crate::safety::SafetyGateConfig;
use crate::tools::TOOL_SCHEMAS;

pub const OPERATOR_PROJECTION_SCHEMA_VERSION: &str = "agentd-operator-projection/v1";

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
        Ok(Self {
            schema_version: OPERATOR_PROJECTION_SCHEMA_VERSION,
            source: "agentd-read-only",
            read_only: true,
            redaction: "secret-values-redacted",
            runtime: OperatorRuntimeProjection::from_health(&health),
            telemetry,
            audit,
            update: OperatorUpdateProjection::contract_only(),
            adapters: OperatorAdapterProjection::from_tool_manifest(),
            safety: OperatorSafetyProjection::from_gate(&SafetyGateConfig::default_gate()),
        })
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":\"{}\",\"source\":\"{}\",\"read_only\":{},\"redaction\":\"{}\",\"runtime\":{},\"telemetry\":{},\"audit\":{},\"update\":{},\"adapters\":{},\"safety\":{}}}",
            self.schema_version,
            self.source,
            self.read_only,
            self.redaction,
            self.runtime.to_json(),
            self.telemetry.to_json(),
            self.audit.to_json(),
            self.update.to_json(),
            self.adapters.to_json(),
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
            self.safety.to_cli_line(),
        ]
    }

    pub fn to_cli_text(&self) -> String {
        self.to_cli_lines().join("\n")
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
        let journal_path = Some(journal.path().display().to_string());

        let Some(projection) = projection else {
            return Ok(Self {
                journal_path,
                requested_run_id,
                ..Self::empty(None, None)
            });
        };

        Ok(Self::from_runtime_projection(
            journal_path,
            requested_run_id,
            &projection,
            unresolved_effects,
        ))
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
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"journal_path\":{},\"requested_run_id\":{},\"latest_run_id\":{},\"latest_step_id\":{},\"latest_run_status\":\"{}\",\"audit_seal_status\":\"{}\",\"event_count\":{},\"effect_prepared_count\":{},\"commit_sealed_count\":{},\"rollback_pending_count\":{},\"unresolved_effects\":{},\"warning_count\":{},\"warnings\":{}}}",
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
            string_array_json(&self.warnings)
        )
    }

    fn to_cli_line(&self) -> String {
        format!(
            "audit journal={} requested_run={} latest_run={} step={} status={} seal={} prepared={} sealed={} rollback_pending={} unresolved_effects={} warnings={}",
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
            self.warning_count
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorUpdateProjection {
    pub slot_strategy: &'static str,
    pub active_slot: &'static str,
    pub inactive_slot: &'static str,
    pub pending_activation: bool,
    pub rollback_available: bool,
    pub status: &'static str,
}

impl OperatorUpdateProjection {
    fn contract_only() -> Self {
        Self {
            slot_strategy: "ab-rootfs-contract",
            active_slot: "unknown",
            inactive_slot: "unknown",
            pending_activation: false,
            rollback_available: false,
            status: "not-configured",
        }
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"slot_strategy\":\"{}\",\"active_slot\":\"{}\",\"inactive_slot\":\"{}\",\"pending_activation\":{},\"rollback_available\":{},\"status\":\"{}\"}}",
            self.slot_strategy,
            self.active_slot,
            self.inactive_slot,
            self.pending_activation,
            self.rollback_available,
            self.status
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

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use super::*;
    use crate::audit::{AuditEvent, AuditEventType};
    use crate::lifecycle::LifecycleConfig;

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
        assert!(projection.safety.fail_closed);

        let json = projection.to_json();
        assert!(json.contains("\"schema_version\":\"agentd-operator-projection/v1\""));
        assert!(json.contains("\"read_only\":true"));
        assert!(json.contains("\"audit_seal_status\":\"sealed\""));
        assert!(json.contains("\"package_manager_status\":\"available\""));
        assert!(json.contains("secret://prod/db"));
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("password=hunter2"));
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
        assert!(projection.to_cli_text().contains("runtime state=running"));
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
}
