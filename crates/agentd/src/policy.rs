use crate::api::{RiskClass, escape_json};
use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
use crate::tools::RoutedToolCall;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecisionKind {
    Allow,
    Deny,
    PauseForApproval,
}

impl PolicyDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyDecisionKind::Allow => "allow",
            PolicyDecisionKind::Deny => "deny",
            PolicyDecisionKind::PauseForApproval => "pause-for-approval",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalToken {
    pub actor: String,
    pub tool: String,
    pub resource: String,
    pub parameter_hash: String,
    pub expires_at: u64,
    pub policy_version: String,
}

impl ApprovalToken {
    pub fn matches(&self, request: &PolicyRequest) -> bool {
        self.actor == request.actor
            && self.tool == request.tool
            && self.resource == request.resource
            && self.parameter_hash == request.parameter_hash
            && self.policy_version == request.policy_version
            && self.expires_at >= request.now
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    pub actor: String,
    pub tool: String,
    pub resource: String,
    pub risk: RiskClass,
    pub parameter_hash: String,
    pub policy_version: String,
    pub now: u64,
}

impl PolicyRequest {
    pub fn from_routed(actor: impl Into<String>, routed: &RoutedToolCall) -> Self {
        let resource = routed
            .normalized_params
            .iter()
            .find(|(key, _)| key == "path" || key == "service" || key == "url")
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| routed.tool.to_string());
        Self {
            actor: actor.into(),
            tool: routed.tool.to_string(),
            resource,
            risk: routed.risk,
            parameter_hash: stable_parameter_hash(&routed.normalized_params),
            policy_version: "policy-v1".to_string(),
            now: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub kind: PolicyDecisionKind,
    pub risk: RiskClass,
    pub reason: String,
}

impl PolicyDecision {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"decision\":\"{}\",\"risk\":\"{}\",\"reason\":\"{}\"}}",
            self.kind.as_str(),
            self.risk.as_str(),
            escape_json(&self.reason)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityLease {
    pub lease_id: String,
    pub actor: String,
    pub tool: String,
    pub resource: String,
    pub parameter_hash: String,
    pub expires_at: u64,
    pub policy_version: String,
    pub risk: RiskClass,
}

impl CapabilityLease {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"lease_id\":\"{}\",\"actor\":\"{}\",\"tool\":\"{}\",\"resource\":\"{}\",\"parameter_hash\":\"{}\",\"expires_at\":{},\"policy_version\":\"{}\",\"risk\":\"{}\"}}",
            escape_json(&self.lease_id),
            escape_json(&self.actor),
            escape_json(&self.tool),
            escape_json(&self.resource),
            escape_json(&self.parameter_hash),
            self.expires_at,
            escape_json(&self.policy_version),
            self.risk.as_str()
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    pub fn evaluate(
        &self,
        request: &PolicyRequest,
        approval: Option<&ApprovalToken>,
    ) -> PolicyDecision {
        match request.risk {
            RiskClass::ReadOnly => PolicyDecision {
                kind: PolicyDecisionKind::Allow,
                risk: request.risk,
                reason: "read-only semantic tool is allowed".to_string(),
            },
            RiskClass::WriteWithDiff
            | RiskClass::ExecuteWithConfirmation
            | RiskClass::PrivilegedWithHumanApproval => {
                if approval.is_some_and(|token| token.matches(request)) {
                    PolicyDecision {
                        kind: PolicyDecisionKind::Allow,
                        risk: request.risk,
                        reason: "matching approval token bound to exact parameters".to_string(),
                    }
                } else {
                    PolicyDecision {
                        kind: PolicyDecisionKind::PauseForApproval,
                        risk: request.risk,
                        reason: "high-risk action requires exact approval token".to_string(),
                    }
                }
            }
            RiskClass::Never => PolicyDecision {
                kind: PolicyDecisionKind::Deny,
                risk: request.risk,
                reason: "normal mode denies this capability".to_string(),
            },
        }
    }

    pub fn acquire_lease(
        &self,
        request: &PolicyRequest,
        decision: &PolicyDecision,
    ) -> Result<CapabilityLease, String> {
        if decision.kind != PolicyDecisionKind::Allow {
            return Err(decision.reason.clone());
        }
        Ok(CapabilityLease {
            lease_id: format!("lease-{}-{}", request.tool, request.parameter_hash),
            actor: request.actor.clone(),
            tool: request.tool.clone(),
            resource: request.resource.clone(),
            parameter_hash: request.parameter_hash.clone(),
            expires_at: request.now + 60,
            policy_version: request.policy_version.clone(),
            risk: request.risk,
        })
    }

    pub fn record_decision(
        &self,
        journal: &AuditJournal,
        run_id: impl Into<String>,
        step_id: impl Into<String>,
        request: &PolicyRequest,
        decision: &PolicyDecision,
    ) -> std::io::Result<()> {
        let mut event = AuditEvent::new(
            AuditEventType::PolicyEvaluated,
            run_id,
            step_id,
            request.actor.as_str(),
            format!(
                "decision={} tool={} resource={} risk={} reason={}",
                decision.kind.as_str(),
                request.tool,
                request.resource,
                decision.risk.as_str(),
                decision.reason
            ),
        );
        event.policy_version = request.policy_version.clone();
        event.tool_version = "tool-v1".to_string();
        event.parameter_hash = request.parameter_hash.clone();
        journal.append(&event)
    }
}

pub fn stable_parameter_hash(params: &[(String, String)]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for (key, value) in params {
        for byte in key.bytes().chain([b'=']).chain(value.bytes()).chain([b';']) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::SemanticToolCall;
    use crate::tools::ToolRouter;

    fn test_journal(name: &str) -> AuditJournal {
        let path =
            std::env::temp_dir().join(format!("agentd-policy-{name}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        AuditJournal::new(path)
    }

    fn request_for(tool: &str, params: Vec<(&str, &str)>) -> PolicyRequest {
        let routed = ToolRouter
            .route(&SemanticToolCall::new(tool, params))
            .expect("route tool");
        PolicyRequest::from_routed("operator", &routed)
    }

    #[test]
    fn allows_read_only_tools_and_issues_lease() {
        let evaluator = PolicyEvaluator;
        let request = request_for("svc.status", vec![("service", "nginx")]);
        let decision = evaluator.evaluate(&request, None);
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
        let lease = evaluator.acquire_lease(&request, &decision).expect("lease");
        assert_eq!(lease.actor, "operator");
        assert_eq!(lease.tool, "svc.status");
        assert_eq!(lease.resource, "nginx");
        assert_eq!(lease.risk, RiskClass::ReadOnly);
    }

    #[test]
    fn pauses_write_with_diff_without_matching_approval() {
        let evaluator = PolicyEvaluator;
        let request = request_for(
            "fs.write.diff",
            vec![("path", "/etc/nginx/nginx.conf"), ("content_hash", "abc")],
        );
        let decision = evaluator.evaluate(&request, None);
        assert_eq!(decision.kind, PolicyDecisionKind::PauseForApproval);
        assert!(evaluator.acquire_lease(&request, &decision).is_err());
    }

    #[test]
    fn approval_token_must_match_exact_parameter_hash() {
        let evaluator = PolicyEvaluator;
        let request = request_for(
            "fs.write.diff",
            vec![("path", "/etc/nginx/nginx.conf"), ("content_hash", "abc")],
        );
        let mut token = ApprovalToken {
            actor: request.actor.clone(),
            tool: request.tool.clone(),
            resource: request.resource.clone(),
            parameter_hash: request.parameter_hash.clone(),
            expires_at: 60,
            policy_version: request.policy_version.clone(),
        };
        let decision = evaluator.evaluate(&request, Some(&token));
        assert_eq!(decision.kind, PolicyDecisionKind::Allow);

        token.parameter_hash = "mutated".to_string();
        let decision = evaluator.evaluate(&request, Some(&token));
        assert_eq!(decision.kind, PolicyDecisionKind::PauseForApproval);
    }

    #[test]
    fn denies_never_capability() {
        let evaluator = PolicyEvaluator;
        let request = PolicyRequest {
            actor: "operator".to_string(),
            tool: "shell.exec".to_string(),
            resource: "host".to_string(),
            risk: RiskClass::Never,
            parameter_hash: "hash".to_string(),
            policy_version: "policy-v1".to_string(),
            now: 0,
        };
        let decision = evaluator.evaluate(&request, None);
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(evaluator.acquire_lease(&request, &decision).is_err());
    }

    #[test]
    fn records_denied_decision_without_executing() {
        let evaluator = PolicyEvaluator;
        let journal = test_journal("deny");
        let request = PolicyRequest {
            actor: "operator".to_string(),
            tool: "shell.exec".to_string(),
            resource: "host".to_string(),
            risk: RiskClass::Never,
            parameter_hash: stable_parameter_hash(&[("cmd".to_string(), "id".to_string())]),
            policy_version: "policy-v1".to_string(),
            now: 0,
        };
        let decision = evaluator.evaluate(&request, None);
        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        evaluator
            .record_decision(&journal, "run-policy", "step-denied", &request, &decision)
            .expect("record decision");
        assert!(evaluator.acquire_lease(&request, &decision).is_err());

        let lines = journal.event_lines().expect("read journal");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"event_type\":\"PolicyEvaluated\""));
        assert!(lines[0].contains("decision=deny"));
        assert!(lines[0].contains("shell.exec"));
        assert!(lines[0].contains(&request.parameter_hash));
        assert!(!lines[0].contains("EffectPrepared"));
        assert!(!lines[0].contains("EffectObserved"));
    }
}
