use crate::agent_core::service_recovery::{
    AgentCoreServiceRecovery, AgentRestartApproval, AgentServiceRecoveryReport,
};
use crate::api::escape_json;
use crate::audit::AuditJournal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartApproval {
    Approved,
    Denied,
}

impl RestartApproval {
    pub fn as_str(self) -> &'static str {
        match self {
            RestartApproval::Approved => "approved",
            RestartApproval::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFixture {
    pub service: String,
    pub running: bool,
    pub http_healthy: bool,
    pub config_valid: bool,
    pub restart_count: u32,
}

impl ServiceFixture {
    pub fn degraded_nginx() -> Self {
        Self {
            service: "nginx".to_string(),
            running: false,
            http_healthy: false,
            config_valid: true,
            restart_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowObservation {
    pub step_id: String,
    pub tool: String,
    pub result: String,
}

impl WorkflowObservation {
    fn to_json(&self) -> String {
        format!(
            "{{\"step_id\":\"{}\",\"tool\":\"{}\",\"result\":\"{}\"}}",
            escape_json(&self.step_id),
            escape_json(&self.tool),
            escape_json(&self.result)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecoveryReport {
    pub run_id: String,
    pub service: String,
    pub restart_policy_decision: String,
    pub restart_executed: bool,
    pub final_health_ok: bool,
    pub observations: Vec<WorkflowObservation>,
    pub summary: String,
}

impl ServiceRecoveryReport {
    pub fn to_json(&self) -> String {
        let observations = self
            .observations
            .iter()
            .map(WorkflowObservation::to_json)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"run_id\":\"{}\",\"service\":\"{}\",\"restart_policy_decision\":\"{}\",\"restart_executed\":{},\"final_health_ok\":{},\"observations\":[{}],\"summary\":\"{}\"}}",
            escape_json(&self.run_id),
            escape_json(&self.service),
            escape_json(&self.restart_policy_decision),
            self.restart_executed,
            self.final_health_ok,
            observations,
            escape_json(&self.summary)
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ServiceRecoveryWorkflow;

impl ServiceRecoveryWorkflow {
    pub fn run(
        &self,
        journal: &AuditJournal,
        fixture: ServiceFixture,
        approval: RestartApproval,
    ) -> Result<ServiceRecoveryReport, String> {
        let report = AgentCoreServiceRecovery.run(
            journal,
            &fixture.service,
            match approval {
                RestartApproval::Approved => AgentRestartApproval::Approved,
                RestartApproval::Denied => AgentRestartApproval::Denied,
            },
        )?;
        Ok(report.into())
    }
}

impl From<AgentServiceRecoveryReport> for ServiceRecoveryReport {
    fn from(report: AgentServiceRecoveryReport) -> Self {
        Self {
            run_id: report.run_id,
            service: report.service,
            restart_policy_decision: report.restart_policy_decision,
            restart_executed: report.restart_executed,
            final_health_ok: report.final_health_ok,
            observations: report
                .observations
                .into_iter()
                .map(|observation| WorkflowObservation {
                    step_id: observation.step_id,
                    tool: observation.tool,
                    result: observation.result,
                })
                .collect(),
            summary: report.summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_journal(name: &str) -> AuditJournal {
        let path = std::env::temp_dir().join(format!(
            "agentd-service-recovery-{name}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    #[test]
    fn happy_path_runs_diagnostics_restart_and_verified_summary() {
        let journal = test_journal("approved");
        let report = ServiceRecoveryWorkflow
            .run(
                &journal,
                ServiceFixture::degraded_nginx(),
                RestartApproval::Approved,
            )
            .expect("workflow");
        assert!(report.restart_executed);
        assert!(report.final_health_ok);
        assert!(
            report
                .summary
                .contains("final status and http check show healthy")
        );
        for tool in [
            "svc.logs",
            "svc.status",
            "http.check",
            "config.test",
            "svc.restart",
        ] {
            assert!(
                report
                    .observations
                    .iter()
                    .any(|observation| observation.tool == tool),
                "missing {tool}"
            );
        }
        let lines = journal.event_lines().expect("read journal");
        for expected in [
            "IntentReceived",
            "PlanFrozen",
            "PolicyEvaluated",
            "ApprovalBound",
            "EffectPrepared",
            "EffectObserved",
            "CommitSealed",
        ] {
            assert!(
                lines.iter().any(|line| line.contains(expected)),
                "missing {expected}"
            );
        }
        assert!(lines.iter().any(|line| line.contains("svc.restart")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("ApprovalBound") && line.contains("approval granted"))
        );
    }

    #[test]
    fn denied_restart_path_prepares_no_restart_effect() {
        let journal = test_journal("denied");
        let report = ServiceRecoveryWorkflow
            .run(
                &journal,
                ServiceFixture::degraded_nginx(),
                RestartApproval::Denied,
            )
            .expect("workflow");
        assert!(!report.restart_executed);
        assert!(!report.final_health_ok);
        assert!(report.summary.contains("no restart effect was prepared"));
        let lines = journal.event_lines().expect("read journal");
        assert!(lines.iter().any(|line| line.contains("pause-for-approval")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("ApprovalBound") && line.contains("approval denied"))
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("EffectPrepared") && line.contains("svc.restart"))
        );
        assert!(!lines.iter().any(|line| line.contains("restart_count=1")));
    }

    #[test]
    fn read_only_diagnostics_are_sealed_without_approval() {
        let journal = test_journal("readonly");
        let _ = ServiceRecoveryWorkflow
            .run(
                &journal,
                ServiceFixture::degraded_nginx(),
                RestartApproval::Denied,
            )
            .expect("workflow");
        let lines = journal.event_lines().expect("read journal");
        for tool in ["svc.logs", "svc.status", "http.check", "config.test"] {
            assert!(
                lines
                    .iter()
                    .any(|line| { line.contains("EffectObserved") && line.contains(tool) })
            );
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("CommitSealed") && line.contains(tool))
            );
        }
    }
}
