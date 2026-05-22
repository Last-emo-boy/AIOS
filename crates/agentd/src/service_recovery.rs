use crate::api::{escape_json, SemanticToolCall};
use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
use crate::policy::{
    ApprovalToken, CapabilityLease, PolicyDecisionKind, PolicyEvaluator, PolicyRequest,
};
use crate::sandbox::{SandboxCompiler, SandboxExecutor, SandboxOperation};
use crate::tools::ToolRouter;

const RUN_ID: &str = "run-service-recovery";
const ACTOR: &str = "operator";

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

    fn logs(&self) -> String {
        if self.http_healthy {
            "nginx access log shows 200 for /healthz after restart".to_string()
        } else {
            "nginx error log shows upstream 502 and worker not accepting connections".to_string()
        }
    }

    fn status(&self) -> String {
        if self.running {
            format!("{} running restart_count={}", self.service, self.restart_count)
        } else {
            format!("{} inactive restart_count={}", self.service, self.restart_count)
        }
    }

    fn http_check(&self) -> String {
        if self.http_healthy {
            "http://127.0.0.1/healthz -> 200 OK".to_string()
        } else {
            "http://127.0.0.1/healthz -> 502 Bad Gateway".to_string()
        }
    }

    fn config_test(&self) -> String {
        if self.config_valid {
            format!("{} config syntax ok", self.service)
        } else {
            format!("{} config syntax failed", self.service)
        }
    }

    fn restart(&mut self) -> String {
        self.running = true;
        self.http_healthy = true;
        self.restart_count += 1;
        format!("{} restarted restart_count={}", self.service, self.restart_count)
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
        mut fixture: ServiceFixture,
        approval: RestartApproval,
    ) -> Result<ServiceRecoveryReport, String> {
        journal
            .append(&AuditEvent::new(
                AuditEventType::IntentReceived,
                RUN_ID,
                "intent",
                ACTOR,
                format!("recover {} service and explain observed changes", fixture.service),
            ))
            .map_err(|error| error.to_string())?;
        journal
            .append(&AuditEvent::new(
                AuditEventType::PlanFrozen,
                RUN_ID,
                "plan",
                "agentd",
                "diagnostics: svc.logs, svc.status, http.check, config.test; restart requires approval",
            ))
            .map_err(|error| error.to_string())?;

        let mut observations = Vec::new();
        for tool in ["svc.logs", "svc.status", "http.check", "config.test"] {
            let observation = self.run_read_only_tool(journal, &fixture, tool, "diagnose")?;
            observations.push(observation);
        }

        let restart_decision = self.evaluate_restart(journal, &fixture, approval)?;
        let mut restart_executed = false;
        if restart_decision.kind == PolicyDecisionKind::Allow {
            restart_executed = true;
            self.append_effect(
                journal,
                "restart",
                "svc.restart",
                &restart_decision.lease,
                AuditEventType::EffectPrepared,
                format!("prepared svc.restart service={}", fixture.service),
            )?;
            let result = fixture.restart();
            self.append_effect(
                journal,
                "restart",
                "svc.restart",
                &restart_decision.lease,
                AuditEventType::EffectObserved,
                result.clone(),
            )?;
            observations.push(WorkflowObservation {
                step_id: "restart".to_string(),
                tool: "svc.restart".to_string(),
                result,
            });

            for tool in ["svc.status", "http.check"] {
                let observation = self.run_read_only_tool(journal, &fixture, tool, "verify")?;
                observations.push(observation);
            }

            self.append_effect(
                journal,
                "restart",
                "svc.restart",
                &restart_decision.lease,
                AuditEventType::CommitSealed,
                format!("verified svc.restart service={} health_ok=true", fixture.service),
            )?;
        }

        let final_health_ok = fixture.running && fixture.http_healthy && fixture.config_valid;
        let summary = if restart_executed {
            format!(
                "Checked logs/status/http/config for {}; restart was approved and executed; final status and http check show healthy.",
                fixture.service
            )
        } else {
            format!(
                "Checked logs/status/http/config for {}; restart paused for approval and was denied, so no restart effect was prepared.",
                fixture.service
            )
        };

        Ok(ServiceRecoveryReport {
            run_id: RUN_ID.to_string(),
            service: fixture.service,
            restart_policy_decision: restart_decision.decision,
            restart_executed,
            final_health_ok,
            observations,
            summary,
        })
    }

    fn run_read_only_tool(
        &self,
        journal: &AuditJournal,
        fixture: &ServiceFixture,
        tool: &str,
        phase: &str,
    ) -> Result<WorkflowObservation, String> {
        let call = match tool {
            "svc.logs" => SemanticToolCall::new(
                "svc.logs",
                vec![("service", fixture.service.as_str()), ("last", "200")],
            ),
            "svc.status" => {
                SemanticToolCall::new("svc.status", vec![("service", fixture.service.as_str())])
            }
            "http.check" => SemanticToolCall::new(
                "http.check",
                vec![("url", "http://127.0.0.1/healthz")],
            ),
            "config.test" => {
                SemanticToolCall::new("config.test", vec![("service", fixture.service.as_str())])
            }
            other => return Err(format!("unsupported diagnostic tool: {other}")),
        };
        let routed = ToolRouter.route(&call).map_err(|error| error.reason)?;
        let request = PolicyRequest::from_routed(ACTOR, &routed);
        let evaluator = PolicyEvaluator;
        let decision = evaluator.evaluate(&request, None);
        evaluator
            .record_decision(journal, RUN_ID, format!("{phase}-{tool}"), &request, &decision)
            .map_err(|error| error.to_string())?;
        let lease = evaluator
            .acquire_lease(&request, &decision)
            .map_err(|error| error.to_string())?;
        let profile = SandboxCompiler
            .compile(&lease)
            .map_err(|error| error.reason())?;
        let sandbox_report = SandboxExecutor.evaluate(
            &profile,
            SandboxOperation::ReadDiagnostic {
                label: tool.to_string(),
            },
        );
        if sandbox_report.decision != crate::sandbox::SandboxDecision::Allowed {
            return Err(sandbox_report.reason);
        }

        let step_id = format!("{phase}-{tool}");
        self.append_effect(
            journal,
            &step_id,
            tool,
            &lease,
            AuditEventType::EffectPrepared,
            format!("prepared read-only {tool} service={}", fixture.service),
        )?;
        let result = match tool {
            "svc.logs" => fixture.logs(),
            "svc.status" => fixture.status(),
            "http.check" => fixture.http_check(),
            "config.test" => fixture.config_test(),
            _ => unreachable!("checked above"),
        };
        self.append_effect(
            journal,
            &step_id,
            tool,
            &lease,
            AuditEventType::EffectObserved,
            format!("observed {tool}: {result}"),
        )?;
        self.append_effect(
            journal,
            &step_id,
            tool,
            &lease,
            AuditEventType::CommitSealed,
            format!("sealed read-only {tool}"),
        )?;
        Ok(WorkflowObservation {
            step_id,
            tool: tool.to_string(),
            result,
        })
    }

    fn evaluate_restart(
        &self,
        journal: &AuditJournal,
        fixture: &ServiceFixture,
        approval: RestartApproval,
    ) -> Result<RestartGate, String> {
        let call = SemanticToolCall::new("svc.restart", vec![("service", fixture.service.as_str())]);
        let routed = ToolRouter.route(&call).map_err(|error| error.reason)?;
        let request = PolicyRequest::from_routed(ACTOR, &routed);
        let evaluator = PolicyEvaluator;
        let paused = evaluator.evaluate(&request, None);
        evaluator
            .record_decision(journal, RUN_ID, "restart-policy", &request, &paused)
            .map_err(|error| error.to_string())?;

        if approval == RestartApproval::Denied {
            journal
                .append(&AuditEvent::new(
                    AuditEventType::ApprovalBound,
                    RUN_ID,
                    "restart-approval",
                    ACTOR,
                    "restart approval denied; no svc.restart effect prepared",
                ))
                .map_err(|error| error.to_string())?;
            return Ok(RestartGate {
                decision: paused.kind.as_str().to_string(),
                kind: PolicyDecisionKind::PauseForApproval,
                lease: CapabilityLease {
                    lease_id: "unissued".to_string(),
                    actor: request.actor,
                    tool: request.tool,
                    resource: request.resource,
                    parameter_hash: request.parameter_hash,
                    expires_at: request.now,
                    policy_version: request.policy_version,
                    risk: request.risk,
                },
            });
        }

        let token = ApprovalToken {
            actor: request.actor.clone(),
            tool: request.tool.clone(),
            resource: request.resource.clone(),
            parameter_hash: request.parameter_hash.clone(),
            expires_at: 60,
            policy_version: request.policy_version.clone(),
        };
        let allowed = evaluator.evaluate(&request, Some(&token));
        evaluator
            .record_decision(journal, RUN_ID, "restart-policy-approved", &request, &allowed)
            .map_err(|error| error.to_string())?;
        let lease = evaluator
            .acquire_lease(&request, &allowed)
            .map_err(|error| error.to_string())?;
        let mut event = AuditEvent::new(
            AuditEventType::ApprovalBound,
            RUN_ID,
            "restart-approval",
            ACTOR,
            format!(
                "restart approval approved lease_id={} service={}",
                lease.lease_id, fixture.service
            ),
        );
        event.policy_version = lease.policy_version.clone();
        event.tool_version = "svc.restart-v1".to_string();
        event.parameter_hash = lease.parameter_hash.clone();
        journal.append(&event).map_err(|error| error.to_string())?;
        Ok(RestartGate {
            decision: allowed.kind.as_str().to_string(),
            kind: allowed.kind,
            lease,
        })
    }

    fn append_effect(
        &self,
        journal: &AuditJournal,
        step_id: &str,
        tool: &str,
        lease: &CapabilityLease,
        event_type: AuditEventType,
        summary: String,
    ) -> Result<(), String> {
        let mut event = AuditEvent::new(event_type, RUN_ID, step_id, ACTOR, summary);
        event.policy_version = lease.policy_version.clone();
        event.tool_version = format!("{tool}-v1");
        event.parameter_hash = lease.parameter_hash.clone();
        journal.append(&event).map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RestartGate {
    decision: String,
    kind: PolicyDecisionKind,
    lease: CapabilityLease,
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
        assert!(report.summary.contains("final status and http check show healthy"));
        for tool in ["svc.logs", "svc.status", "http.check", "config.test", "svc.restart"] {
            assert!(
                report.observations.iter().any(|observation| observation.tool == tool),
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
            assert!(lines.iter().any(|line| line.contains(expected)), "missing {expected}");
        }
        assert!(lines.iter().any(|line| line.contains("svc.restart")));
        assert!(lines.iter().any(|line| line.contains("restart approval approved")));
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
        assert!(lines.iter().any(|line| line.contains("restart approval denied")));
        assert!(!lines
            .iter()
            .any(|line| line.contains("EffectPrepared") && line.contains("svc.restart")));
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
            assert!(lines.iter().any(|line| {
                line.contains("EffectObserved") && line.contains(tool)
            }));
            assert!(lines
                .iter()
                .any(|line| line.contains("CommitSealed") && line.contains(tool)));
        }
    }
}
