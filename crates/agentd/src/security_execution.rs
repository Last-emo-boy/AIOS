pub mod effect_envelope {
    use std::fmt;

    use crate::agent_core::model::contains_secret_value;
    use crate::api::{escape_json, CommitId, RiskClass, VerificationResult};
    use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
    use crate::policy::{
        stable_parameter_hash, CapabilityLease, PolicyDecision, PolicyDecisionKind,
    };
    use crate::rollback::RollbackHandle;
    use crate::sandbox::SandboxProfile;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EffectEnvelopeState {
        Draft,
        Prepared,
        Observed,
        Verified,
        Sealed,
        RollbackPending,
        RolledBack,
        FailedClosed,
    }

    impl EffectEnvelopeState {
        pub fn as_str(self) -> &'static str {
            match self {
                EffectEnvelopeState::Draft => "Draft",
                EffectEnvelopeState::Prepared => "Prepared",
                EffectEnvelopeState::Observed => "Observed",
                EffectEnvelopeState::Verified => "Verified",
                EffectEnvelopeState::Sealed => "Sealed",
                EffectEnvelopeState::RollbackPending => "RollbackPending",
                EffectEnvelopeState::RolledBack => "RolledBack",
                EffectEnvelopeState::FailedClosed => "FailedClosed",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum EffectEnvelopeError {
        InvalidTransition {
            from: EffectEnvelopeState,
            action: &'static str,
            reason: String,
        },
        SecretValue {
            field: String,
        },
        Io(String),
    }

    impl EffectEnvelopeError {
        pub fn reason(&self) -> String {
            match self {
                EffectEnvelopeError::InvalidTransition {
                    from,
                    action,
                    reason,
                } => format!(
                    "invalid envelope transition from {} via {action}: {reason}",
                    from.as_str()
                ),
                EffectEnvelopeError::SecretValue { field } => {
                    format!("secret-like value is not serializable in {field}")
                }
                EffectEnvelopeError::Io(error) => error.clone(),
            }
        }
    }

    impl fmt::Display for EffectEnvelopeError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.reason())
        }
    }

    impl From<std::io::Error> for EffectEnvelopeError {
        fn from(value: std::io::Error) -> Self {
            EffectEnvelopeError::Io(value.to_string())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EffectEnvelope {
        pub run_id: String,
        pub step_id: String,
        pub tool: String,
        pub normalized_params: Vec<(String, String)>,
        pub policy_decision: PolicyDecision,
        pub lease: Option<CapabilityLease>,
        pub sandbox_profile: Option<SandboxProfile>,
        pub execution_profile_summary: Option<String>,
        pub prepared_event: Option<AuditEvent>,
        pub observed_event: Option<AuditEvent>,
        pub verification_result: Option<VerificationResult>,
        pub rollback_handle: Option<RollbackHandle>,
        pub commit_id: Option<CommitId>,
        pub state: EffectEnvelopeState,
    }

    impl EffectEnvelope {
        pub fn draft(
            run_id: impl Into<String>,
            step_id: impl Into<String>,
            tool: impl Into<String>,
            normalized_params: Vec<(String, String)>,
            policy_decision: PolicyDecision,
        ) -> Result<Self, EffectEnvelopeError> {
            let envelope = Self {
                run_id: run_id.into(),
                step_id: step_id.into(),
                tool: tool.into(),
                normalized_params: sort_params(normalized_params),
                policy_decision,
                lease: None,
                sandbox_profile: None,
                execution_profile_summary: None,
                prepared_event: None,
                observed_event: None,
                verification_result: None,
                rollback_handle: None,
                commit_id: None,
                state: EffectEnvelopeState::Draft,
            };
            envelope.validate_for_serialization()?;
            Ok(envelope)
        }

        pub fn parameter_hash(&self) -> String {
            stable_parameter_hash(&sort_params(self.normalized_params.clone()))
        }

        pub fn set_execution_profile_summary(
            &mut self,
            summary: impl Into<String>,
        ) -> Result<(), EffectEnvelopeError> {
            self.require_state(EffectEnvelopeState::Draft, "set_execution_profile_summary")?;
            let summary = summary.into();
            ensure_no_secret("execution_profile_summary", &summary)?;
            self.execution_profile_summary = Some(summary);
            Ok(())
        }

        pub fn prepare(
            &mut self,
            journal: &AuditJournal,
            actor: &str,
            lease: CapabilityLease,
            sandbox_profile: Option<SandboxProfile>,
            rollback_handle: Option<RollbackHandle>,
        ) -> Result<(), EffectEnvelopeError> {
            self.require_state(EffectEnvelopeState::Draft, "prepare")?;
            ensure_no_secret("actor", actor)?;
            self.validate_lease(&lease)?;
            if self.policy_decision.kind != PolicyDecisionKind::Allow {
                return Err(self.invalid(
                    "prepare",
                    "only an allow policy decision can prepare a side effect",
                ));
            }
            if lease.risk == RiskClass::WriteWithDiff && rollback_handle.is_none() {
                return Err(self.invalid(
                    "prepare",
                    "write-with-diff effects require a rollback handle before execution",
                ));
            }
            if let Some(profile) = &sandbox_profile {
                ensure_no_secret("sandbox_profile", &profile.to_json())?;
            }
            if let Some(handle) = &rollback_handle {
                ensure_no_secret("rollback_handle", &handle.to_json())?;
            }

            self.lease = Some(lease);
            self.sandbox_profile = sandbox_profile;
            self.rollback_handle = rollback_handle;
            let event = self.audit_event(
                AuditEventType::EffectPrepared,
                actor,
                format!(
                    "prepared tool={} risk={} parameter_hash={} policy_reason={} execution_profile_summary={}",
                    self.tool,
                    self.risk().as_str(),
                    self.parameter_hash(),
                    self.policy_decision.reason,
                    self.execution_profile_summary.as_deref().unwrap_or("none")
                ),
            )?;
            journal.append(&event)?;
            self.prepared_event = Some(event);
            self.state = EffectEnvelopeState::Prepared;
            Ok(())
        }

        pub fn observe(
            &mut self,
            journal: &AuditJournal,
            actor: &str,
            summary: impl Into<String>,
        ) -> Result<(), EffectEnvelopeError> {
            self.require_state(EffectEnvelopeState::Prepared, "observe")?;
            ensure_no_secret("actor", actor)?;
            let summary = summary.into();
            ensure_no_secret("observation_summary", &summary)?;
            let mut event = self.audit_event(
                AuditEventType::EffectObserved,
                actor,
                format!("observed tool={} {}", self.tool, summary),
            )?;
            event.parent_event = Some(AuditEventType::EffectPrepared.as_str().to_string());
            journal.append(&event)?;
            self.observed_event = Some(event);
            self.state = EffectEnvelopeState::Observed;
            Ok(())
        }

        pub fn verify(
            &mut self,
            journal: &AuditJournal,
            actor: &str,
            verification_result: VerificationResult,
        ) -> Result<(), EffectEnvelopeError> {
            self.require_state(EffectEnvelopeState::Observed, "verify")?;
            ensure_no_secret("actor", actor)?;
            ensure_no_secret("verification_reason", &verification_result.reason)?;
            let success = verification_result.success;
            self.verification_result = Some(verification_result);
            if success {
                self.state = EffectEnvelopeState::Verified;
                return Ok(());
            }
            if self.risk() == RiskClass::WriteWithDiff {
                return self.append_rollback_pending(
                    journal,
                    actor,
                    "write-with-diff verification failed",
                );
            }
            self.state = EffectEnvelopeState::FailedClosed;
            Ok(())
        }

        pub fn seal(
            &mut self,
            journal: &AuditJournal,
            actor: &str,
            commit_id: CommitId,
        ) -> Result<(), EffectEnvelopeError> {
            self.require_state(EffectEnvelopeState::Verified, "seal")?;
            ensure_no_secret("actor", actor)?;
            ensure_no_secret("commit_id", &commit_id.0)?;
            if !self
                .verification_result
                .as_ref()
                .is_some_and(|result| result.success)
            {
                return Err(self.invalid(
                    "seal",
                    "CommitSealed requires a successful verification result",
                ));
            }
            let event = self.audit_event(
                AuditEventType::CommitSealed,
                actor,
                format!("commit sealed tool={} commit_id={}", self.tool, commit_id.0),
            )?;
            journal.append(&event)?;
            self.commit_id = Some(commit_id);
            self.state = EffectEnvelopeState::Sealed;
            Ok(())
        }

        pub fn mark_rollback_pending(
            &mut self,
            journal: &AuditJournal,
            actor: &str,
            reason: impl Into<String>,
        ) -> Result<(), EffectEnvelopeError> {
            match self.state {
                EffectEnvelopeState::Prepared
                | EffectEnvelopeState::Observed
                | EffectEnvelopeState::Verified => {}
                _ => {
                    return Err(self.invalid(
                        "mark_rollback_pending",
                        "rollback can only be requested for prepared or observed effects",
                    ));
                }
            }
            ensure_no_secret("actor", actor)?;
            let reason = reason.into();
            ensure_no_secret("rollback_reason", &reason)?;
            self.append_rollback_pending(journal, actor, reason)
        }

        pub fn mark_rolled_back(
            &mut self,
            journal: &AuditJournal,
            actor: &str,
            summary: impl Into<String>,
        ) -> Result<(), EffectEnvelopeError> {
            self.require_state(EffectEnvelopeState::RollbackPending, "mark_rolled_back")?;
            ensure_no_secret("actor", actor)?;
            let summary = summary.into();
            ensure_no_secret("rollback_summary", &summary)?;
            let event = self.audit_event(
                AuditEventType::RollbackObserved,
                actor,
                format!("rollback observed tool={} {}", self.tool, summary),
            )?;
            journal.append(&event)?;
            self.state = EffectEnvelopeState::RolledBack;
            Ok(())
        }

        pub fn fail_closed(
            &mut self,
            reason: impl Into<String>,
        ) -> Result<(), EffectEnvelopeError> {
            if matches!(
                self.state,
                EffectEnvelopeState::Sealed
                    | EffectEnvelopeState::RollbackPending
                    | EffectEnvelopeState::RolledBack
            ) {
                return Err(self.invalid(
                    "fail_closed",
                    "sealed, rollback-pending, and rolled-back effects are terminal",
                ));
            }
            if self.risk() == RiskClass::WriteWithDiff
                && self
                    .verification_result
                    .as_ref()
                    .is_some_and(|result| !result.success)
            {
                return Err(self.invalid(
                    "fail_closed",
                    "failed write-with-diff verification must enter RollbackPending",
                ));
            }
            let reason = reason.into();
            ensure_no_secret("failure_reason", &reason)?;
            self.state = EffectEnvelopeState::FailedClosed;
            Ok(())
        }

        pub fn to_json(&self) -> Result<String, EffectEnvelopeError> {
            self.validate_for_serialization()?;
            let params = params_json(&sort_params(self.normalized_params.clone()));
            let lease = self
                .lease
                .as_ref()
                .map(CapabilityLease::to_json)
                .unwrap_or_else(|| "null".to_string());
            let sandbox_profile = self
                .sandbox_profile
                .as_ref()
                .map(SandboxProfile::to_json)
                .unwrap_or_else(|| "null".to_string());
            let execution_profile_summary = self
                .execution_profile_summary
                .as_ref()
                .map(|summary| format!("\"{}\"", escape_json(summary)))
                .unwrap_or_else(|| "null".to_string());
            let prepared_event = self
                .prepared_event
                .as_ref()
                .map(AuditEvent::to_json_line)
                .unwrap_or_else(|| "null".to_string());
            let observed_event = self
                .observed_event
                .as_ref()
                .map(AuditEvent::to_json_line)
                .unwrap_or_else(|| "null".to_string());
            let verification_result = self
                .verification_result
                .as_ref()
                .map(verification_json)
                .unwrap_or_else(|| "null".to_string());
            let rollback_handle = self
                .rollback_handle
                .as_ref()
                .map(RollbackHandle::to_json)
                .unwrap_or_else(|| "null".to_string());
            let commit_id = self
                .commit_id
                .as_ref()
                .map(|id| format!("\"{}\"", escape_json(&id.0)))
                .unwrap_or_else(|| "null".to_string());
            Ok(format!(
                "{{\"run_id\":\"{}\",\"step_id\":\"{}\",\"tool\":\"{}\",\"state\":\"{}\",\"normalized_params\":[{}],\"parameter_hash\":\"{}\",\"policy_decision\":{},\"lease\":{},\"sandbox_profile\":{},\"execution_profile_summary\":{},\"prepared_event\":{},\"observed_event\":{},\"verification_result\":{},\"rollback_handle\":{},\"commit_id\":{}}}",
                escape_json(&self.run_id),
                escape_json(&self.step_id),
                escape_json(&self.tool),
                self.state.as_str(),
                params,
                escape_json(&self.parameter_hash()),
                self.policy_decision.to_json(),
                lease,
                sandbox_profile,
                execution_profile_summary,
                prepared_event,
                observed_event,
                verification_result,
                rollback_handle,
                commit_id
            ))
        }

        fn append_rollback_pending(
            &mut self,
            journal: &AuditJournal,
            actor: &str,
            reason: impl Into<String>,
        ) -> Result<(), EffectEnvelopeError> {
            if self.risk() == RiskClass::WriteWithDiff && self.rollback_handle.is_none() {
                return Err(self.invalid(
                    "rollback_pending",
                    "write-with-diff effects require a rollback handle before rollback",
                ));
            }
            let reason = reason.into();
            ensure_no_secret("rollback_reason", &reason)?;
            let event = self.audit_event(
                AuditEventType::RollbackPending,
                actor,
                format!("rollback pending tool={} reason={}", self.tool, reason),
            )?;
            journal.append(&event)?;
            self.state = EffectEnvelopeState::RollbackPending;
            Ok(())
        }

        fn audit_event(
            &self,
            event_type: AuditEventType,
            actor: &str,
            summary: String,
        ) -> Result<AuditEvent, EffectEnvelopeError> {
            ensure_no_secret("event_summary", &summary)?;
            let mut event =
                AuditEvent::new(event_type, &self.run_id, &self.step_id, actor, summary);
            event.parameter_hash = self.parameter_hash();
            if let Some(lease) = &self.lease {
                event.policy_version = lease.policy_version.clone();
                event.tool_version = format!("{}-v1", self.tool);
            }
            Ok(event)
        }

        fn require_state(
            &self,
            expected: EffectEnvelopeState,
            action: &'static str,
        ) -> Result<(), EffectEnvelopeError> {
            if self.state != expected {
                return Err(self.invalid(
                    action,
                    format!(
                        "expected {}, got {}",
                        expected.as_str(),
                        self.state.as_str()
                    ),
                ));
            }
            Ok(())
        }

        fn invalid(&self, action: &'static str, reason: impl Into<String>) -> EffectEnvelopeError {
            EffectEnvelopeError::InvalidTransition {
                from: self.state,
                action,
                reason: reason.into(),
            }
        }

        fn risk(&self) -> RiskClass {
            self.lease
                .as_ref()
                .map(|lease| lease.risk)
                .unwrap_or(self.policy_decision.risk)
        }

        fn validate_lease(&self, lease: &CapabilityLease) -> Result<(), EffectEnvelopeError> {
            if lease.tool != self.tool {
                return Err(self.invalid("prepare", "lease tool must match envelope tool"));
            }
            if lease.parameter_hash != self.parameter_hash() {
                return Err(self.invalid(
                    "prepare",
                    "lease parameter hash must match normalized params",
                ));
            }
            if lease.risk != self.policy_decision.risk {
                return Err(self.invalid("prepare", "lease risk must match policy decision risk"));
            }
            ensure_no_secret("lease", &lease.to_json())?;
            Ok(())
        }

        fn validate_for_serialization(&self) -> Result<(), EffectEnvelopeError> {
            ensure_no_secret("run_id", &self.run_id)?;
            ensure_no_secret("step_id", &self.step_id)?;
            ensure_no_secret("tool", &self.tool)?;
            for (key, value) in &self.normalized_params {
                ensure_safe_param(key, value)?;
            }
            ensure_no_secret("policy_decision", &self.policy_decision.to_json())?;
            if let Some(lease) = &self.lease {
                ensure_no_secret("lease", &lease.to_json())?;
            }
            if let Some(profile) = &self.sandbox_profile {
                ensure_no_secret("sandbox_profile", &profile.to_json())?;
            }
            if let Some(summary) = &self.execution_profile_summary {
                ensure_no_secret("execution_profile_summary", summary)?;
            }
            if let Some(event) = &self.prepared_event {
                ensure_no_secret("prepared_event", &event.to_json_line())?;
            }
            if let Some(event) = &self.observed_event {
                ensure_no_secret("observed_event", &event.to_json_line())?;
            }
            if let Some(result) = &self.verification_result {
                ensure_no_secret("verification_result", &verification_json(result))?;
            }
            if let Some(handle) = &self.rollback_handle {
                ensure_no_secret("rollback_handle", &handle.to_json())?;
            }
            if let Some(commit_id) = &self.commit_id {
                ensure_no_secret("commit_id", &commit_id.0)?;
            }
            Ok(())
        }
    }

    fn params_json(params: &[(String, String)]) -> String {
        params
            .iter()
            .map(|(key, value)| {
                format!(
                    "{{\"key\":\"{}\",\"value\":\"{}\"}}",
                    escape_json(key),
                    escape_json(value)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn verification_json(result: &VerificationResult) -> String {
        format!(
            "{{\"success\":{},\"reason\":\"{}\"}}",
            result.success,
            escape_json(&result.reason)
        )
    }

    fn sort_params(mut params: Vec<(String, String)>) -> Vec<(String, String)> {
        params.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        params
    }

    fn ensure_safe_param(key: &str, value: &str) -> Result<(), EffectEnvelopeError> {
        ensure_no_secret("normalized_params.key", key)?;
        if secret_key(key) && !value.starts_with("secret://") {
            return Err(EffectEnvelopeError::SecretValue {
                field: format!("normalized_params.{key}"),
            });
        }
        ensure_no_secret(format!("normalized_params.{key}"), value)
    }

    fn ensure_no_secret(field: impl Into<String>, value: &str) -> Result<(), EffectEnvelopeError> {
        if contains_secret_value(value) {
            return Err(EffectEnvelopeError::SecretValue {
                field: field.into(),
            });
        }
        Ok(())
    }

    fn secret_key(key: &str) -> bool {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "secret" | "password" | "token" | "apikey" | "api_key"
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::sandbox::{
            CgroupLimits, FileAccess, FilesystemPolicy, LandlockPolicy, MountBind, NamespaceSet,
            NetworkPolicy, SeccompProfile,
        };

        fn test_journal(name: &str) -> AuditJournal {
            let path = std::env::temp_dir().join(format!(
                "agentd-effect-envelope-{name}-{}.jsonl",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            AuditJournal::new(path)
        }

        fn decision(risk: RiskClass) -> PolicyDecision {
            PolicyDecision {
                kind: PolicyDecisionKind::Allow,
                risk,
                reason: "approved by exact policy decision".to_string(),
            }
        }

        fn params(items: Vec<(&str, &str)>) -> Vec<(String, String)> {
            items
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect()
        }

        fn lease(
            tool: &str,
            resource: &str,
            risk: RiskClass,
            normalized_params: &[(String, String)],
        ) -> CapabilityLease {
            CapabilityLease {
                lease_id: format!("lease-{tool}-{}", stable_parameter_hash(normalized_params)),
                actor: "operator".to_string(),
                tool: tool.to_string(),
                resource: resource.to_string(),
                parameter_hash: stable_parameter_hash(normalized_params),
                expires_at: 60,
                policy_version: "policy-v1".to_string(),
                risk,
            }
        }

        fn sandbox_profile(lease: &CapabilityLease) -> SandboxProfile {
            SandboxProfile {
                name: "effect-envelope-test-v1".to_string(),
                lease_id: lease.lease_id.clone(),
                tool: lease.tool.clone(),
                resource: lease.resource.clone(),
                parameter_hash: lease.parameter_hash.clone(),
                policy_version: lease.policy_version.clone(),
                risk: lease.risk,
                no_new_privs: true,
                namespaces: NamespaceSet {
                    user: true,
                    mount: true,
                    pid: true,
                    network: true,
                    cgroup: true,
                },
                cgroup: CgroupLimits {
                    cpu_quota_us: 50_000,
                    cpu_period_us: 100_000,
                    memory_max_bytes: 128 * 1024 * 1024,
                    io_weight: 100,
                    pids_max: 32,
                },
                seccomp: SeccompProfile {
                    default_action: "errno",
                    allowed_syscalls: vec!["read", "write", "exit", "exit_group"],
                    denied_syscalls: vec!["mount", "ptrace", "bpf"],
                },
                filesystem: FilesystemPolicy {
                    read_only_binds: vec![MountBind {
                        source: "/run".to_string(),
                        target: "/run".to_string(),
                        access: FileAccess::ReadOnly,
                    }],
                    writable_tmpfs: vec!["/tmp/agentd-sandbox".to_string()],
                    persistent_write_allowed: false,
                },
                landlock: LandlockPolicy {
                    enabled_when_supported: true,
                    allowed_read_paths: vec!["/run".to_string()],
                    allowed_write_paths: vec!["/tmp/agentd-sandbox".to_string()],
                },
                network: NetworkPolicy {
                    allow_network: false,
                    allowlist: Vec::new(),
                },
            }
        }

        fn rollback_handle(lease: &CapabilityLease) -> RollbackHandle {
            RollbackHandle {
                rollback_id: format!("rb-{}", lease.parameter_hash),
                target_path: "/etc/agentd.conf".into(),
                base_hash: "base-hash".to_string(),
                proposed_hash: "proposed-hash".to_string(),
                parameter_hash: lease.parameter_hash.clone(),
                policy_version: lease.policy_version.clone(),
                previous_content_path: "/tmp/agentd-shadow/previous.txt".into(),
                proposed_content_path: "/tmp/agentd-shadow/proposed.txt".into(),
                committed: false,
            }
        }

        #[test]
        fn side_effecting_restart_moves_from_prepare_to_seal() {
            let journal = test_journal("restart");
            let normalized_params = params(vec![("service", "nginx")]);
            let restart_lease = lease(
                "svc.restart",
                "nginx",
                RiskClass::ExecuteWithConfirmation,
                &normalized_params,
            );
            let mut envelope = EffectEnvelope::draft(
                "run-restart",
                "restart-nginx",
                "svc.restart",
                normalized_params,
                decision(RiskClass::ExecuteWithConfirmation),
            )
            .expect("draft");

            envelope
                .prepare(
                    &journal,
                    "operator",
                    restart_lease.clone(),
                    Some(sandbox_profile(&restart_lease)),
                    None,
                )
                .expect("prepare");
            assert_eq!(envelope.state, EffectEnvelopeState::Prepared);
            assert_eq!(journal.unresolved_effects().expect("unresolved").len(), 1);

            envelope
                .observe(&journal, "operator", "restart returned success")
                .expect("observe");
            envelope
                .verify(
                    &journal,
                    "operator",
                    VerificationResult {
                        success: true,
                        reason: "health check passed".to_string(),
                    },
                )
                .expect("verify");
            envelope
                .seal(&journal, "operator", CommitId("commit-restart".to_string()))
                .expect("seal");

            assert_eq!(envelope.state, EffectEnvelopeState::Sealed);
            assert!(journal.unresolved_effects().expect("unresolved").is_empty());
            let lines = journal.event_lines().expect("journal");
            let prepared = lines
                .iter()
                .position(|line| line.contains("EffectPrepared"))
                .expect("prepared event");
            let observed = lines
                .iter()
                .position(|line| line.contains("EffectObserved"))
                .expect("observed event");
            let sealed = lines
                .iter()
                .position(|line| line.contains("CommitSealed"))
                .expect("sealed event");
            assert!(prepared < observed && observed < sealed);
        }

        #[test]
        fn rejects_observed_before_prepared() {
            let journal = test_journal("observe-before-prepare");
            let normalized_params = params(vec![("service", "nginx")]);
            let mut envelope = EffectEnvelope::draft(
                "run-invalid",
                "restart-nginx",
                "svc.restart",
                normalized_params,
                decision(RiskClass::ExecuteWithConfirmation),
            )
            .expect("draft");

            let error = envelope
                .observe(&journal, "operator", "should not execute")
                .expect_err("observe must be rejected before prepare");
            assert!(error.reason().contains("expected Prepared"));
            assert!(journal.event_lines().expect("journal").is_empty());
        }

        #[test]
        fn rejects_commit_sealed_without_successful_verification() {
            let journal = test_journal("seal-without-verification");
            let normalized_params = params(vec![("service", "nginx")]);
            let restart_lease = lease(
                "svc.restart",
                "nginx",
                RiskClass::ExecuteWithConfirmation,
                &normalized_params,
            );
            let mut envelope = EffectEnvelope::draft(
                "run-no-verify",
                "restart-nginx",
                "svc.restart",
                normalized_params,
                decision(RiskClass::ExecuteWithConfirmation),
            )
            .expect("draft");
            envelope
                .prepare(
                    &journal,
                    "operator",
                    restart_lease.clone(),
                    Some(sandbox_profile(&restart_lease)),
                    None,
                )
                .expect("prepare");
            envelope
                .observe(&journal, "operator", "restart returned success")
                .expect("observe");

            let error = envelope
                .seal(
                    &journal,
                    "operator",
                    CommitId("commit-without-verify".to_string()),
                )
                .expect_err("seal needs verification");
            assert!(error.reason().contains("expected Verified"));
            assert!(!journal
                .event_lines()
                .expect("journal")
                .iter()
                .any(|line| line.contains("CommitSealed")));

            envelope
                .verify(
                    &journal,
                    "operator",
                    VerificationResult {
                        success: false,
                        reason: "health check failed".to_string(),
                    },
                )
                .expect("failed verification");
            assert_eq!(envelope.state, EffectEnvelopeState::FailedClosed);
        }

        #[test]
        fn failed_write_with_diff_verification_enters_rollback_pending() {
            let journal = test_journal("write-failed-verification");
            let normalized_params = params(vec![
                ("content_hash", "new-hash"),
                ("path", "/etc/agentd.conf"),
            ]);
            let write_lease = lease(
                "fs.write.diff",
                "/etc/agentd.conf",
                RiskClass::WriteWithDiff,
                &normalized_params,
            );
            let mut envelope = EffectEnvelope::draft(
                "run-write",
                "write-config",
                "fs.write.diff",
                normalized_params,
                decision(RiskClass::WriteWithDiff),
            )
            .expect("draft");
            envelope
                .prepare(
                    &journal,
                    "operator",
                    write_lease.clone(),
                    None,
                    Some(rollback_handle(&write_lease)),
                )
                .expect("prepare");
            envelope
                .observe(&journal, "operator", "write changed target file")
                .expect("observe");
            envelope
                .verify(
                    &journal,
                    "operator",
                    VerificationResult {
                        success: false,
                        reason: "post-write check failed".to_string(),
                    },
                )
                .expect("verification routes to rollback pending");

            assert_eq!(envelope.state, EffectEnvelopeState::RollbackPending);
            let lines = journal.event_lines().expect("journal");
            assert!(lines.iter().any(|line| line.contains("RollbackPending")));
            assert!(!lines.iter().any(|line| line.contains("CommitSealed")));
            assert!(envelope
                .seal(&journal, "operator", CommitId("commit-write".to_string()))
                .is_err());
            assert!(envelope.fail_closed("skip rollback").is_err());
        }

        #[test]
        fn write_with_diff_requires_rollback_handle_before_prepare() {
            let journal = test_journal("write-no-rollback");
            let normalized_params = params(vec![
                ("content_hash", "new-hash"),
                ("path", "/etc/agentd.conf"),
            ]);
            let write_lease = lease(
                "fs.write.diff",
                "/etc/agentd.conf",
                RiskClass::WriteWithDiff,
                &normalized_params,
            );
            let mut envelope = EffectEnvelope::draft(
                "run-write",
                "write-config",
                "fs.write.diff",
                normalized_params,
                decision(RiskClass::WriteWithDiff),
            )
            .expect("draft");
            let error = envelope
                .prepare(&journal, "operator", write_lease, None, None)
                .expect_err("rollback handle required");
            assert!(error.reason().contains("rollback handle"));
            assert!(journal.event_lines().expect("journal").is_empty());
        }

        #[test]
        fn serialization_rejects_secret_values_but_allows_secret_handles() {
            let unsafe_params = params(vec![("token", "abc")]);
            let error = EffectEnvelope::draft(
                "run-secret",
                "step-secret",
                "http.check",
                unsafe_params,
                decision(RiskClass::ReadOnly),
            )
            .expect_err("raw token rejected");
            assert!(error.reason().contains("secret-like"));

            let safe_params = params(vec![("token", "secret://agentos/http-token")]);
            let mut envelope = EffectEnvelope::draft(
                "run-secret",
                "step-secret",
                "http.check",
                safe_params,
                decision(RiskClass::ReadOnly),
            )
            .expect("secret handle accepted");
            let json = envelope.to_json().expect("serialize");
            assert!(json.contains("secret://agentos/http-token"));
            assert!(!json.contains("token=abc"));
            assert!(!json.contains("abc"));

            envelope
                .normalized_params
                .push(("password".to_string(), "hunter2".to_string()));
            let error = envelope.to_json().expect_err("mutated raw secret rejected");
            assert!(error.reason().contains("password"));
        }
    }
}

pub mod policy_adapter {
    use std::fmt;

    use crate::agent_core::model::contains_secret_value;
    use crate::api::{escape_json, RiskClass};
    use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
    use crate::policy::{
        stable_parameter_hash, ApprovalToken, CapabilityLease, PolicyDecision, PolicyDecisionKind,
        PolicyEvaluator, PolicyRequest,
    };
    use crate::runtime_contracts::ExecutionStep;
    use crate::tools::{RoutedToolCall, ToolRejection, ToolRouter};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StepPolicyOutcomeKind {
        Allowed,
        Denied,
        AwaitingApproval,
    }

    impl StepPolicyOutcomeKind {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Allowed => "allowed",
                Self::Denied => "denied",
                Self::AwaitingApproval => "awaiting-approval",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StepPolicyDiagnostic {
        pub reason: String,
        pub policy_version: String,
        pub parameter_hash: String,
        pub authoritative_risk: RiskClass,
        pub planner_risk_hints: Vec<RiskClass>,
    }

    impl StepPolicyDiagnostic {
        pub fn to_json(&self) -> String {
            let hints = self
                .planner_risk_hints
                .iter()
                .map(|risk| format!("\"{}\"", risk.as_str()))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"reason\":\"{}\",\"policy_version\":\"{}\",\"parameter_hash\":\"{}\",\"authoritative_risk\":\"{}\",\"planner_risk_hints\":[{}]}}",
                escape_json(&self.reason),
                escape_json(&self.policy_version),
                escape_json(&self.parameter_hash),
                self.authoritative_risk.as_str(),
                hints
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StepPolicyOutcome {
        pub kind: StepPolicyOutcomeKind,
        pub run_id: String,
        pub step_id: String,
        pub routed: Option<RoutedToolCall>,
        pub request: Option<PolicyRequest>,
        pub decision: PolicyDecision,
        pub lease: Option<CapabilityLease>,
        pub diagnostic: StepPolicyDiagnostic,
    }

    impl StepPolicyOutcome {
        pub fn to_json(&self) -> String {
            let routed = self
                .routed
                .as_ref()
                .map(RoutedToolCall::to_json)
                .unwrap_or_else(|| "null".to_string());
            let request = self
                .request
                .as_ref()
                .map(policy_request_json)
                .unwrap_or_else(|| "null".to_string());
            let lease = self
                .lease
                .as_ref()
                .map(CapabilityLease::to_json)
                .unwrap_or_else(|| "null".to_string());
            format!(
                "{{\"kind\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"routed\":{},\"request\":{},\"decision\":{},\"lease\":{},\"diagnostic\":{}}}",
                self.kind.as_str(),
                escape_json(&self.run_id),
                escape_json(&self.step_id),
                routed,
                request,
                self.decision.to_json(),
                lease,
                self.diagnostic.to_json()
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum StepPolicyError {
        Io(String),
        SecretValue { field: String },
        Lease(String),
    }

    impl StepPolicyError {
        pub fn reason(&self) -> String {
            match self {
                StepPolicyError::Io(error) => error.clone(),
                StepPolicyError::SecretValue { field } => {
                    format!("secret-like value is not allowed in {field}")
                }
                StepPolicyError::Lease(error) => error.clone(),
            }
        }
    }

    impl fmt::Display for StepPolicyError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.reason())
        }
    }

    impl From<std::io::Error> for StepPolicyError {
        fn from(value: std::io::Error) -> Self {
            StepPolicyError::Io(value.to_string())
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct PlanStepPolicyAdapter {
        router: ToolRouter,
        evaluator: PolicyEvaluator,
    }

    impl PlanStepPolicyAdapter {
        pub fn new(router: ToolRouter, evaluator: PolicyEvaluator) -> Self {
            Self { router, evaluator }
        }

        pub fn evaluate_step(
            &self,
            journal: &AuditJournal,
            run_id: &str,
            actor: &str,
            step: &impl ExecutionStep,
            approval: Option<&ApprovalToken>,
        ) -> Result<StepPolicyOutcome, StepPolicyError> {
            self.evaluate_step_at(journal, run_id, actor, step, approval, 0)
        }

        pub fn evaluate_step_at(
            &self,
            journal: &AuditJournal,
            run_id: &str,
            actor: &str,
            step: &impl ExecutionStep,
            approval: Option<&ApprovalToken>,
            now: u64,
        ) -> Result<StepPolicyOutcome, StepPolicyError> {
            ensure_no_secret("run_id", run_id)?;
            ensure_no_secret("actor", actor)?;
            ensure_no_secret("step_id", step.step_id())?;
            let planner_risk_hints = step.planner_risk_hints();

            let routed = match self.router.route(step.call()) {
                Ok(routed) => routed,
                Err(rejection) => {
                    return self.route_denial(
                        journal,
                        run_id,
                        actor,
                        step,
                        rejection,
                        planner_risk_hints,
                    );
                }
            };

            let mut request = PolicyRequest::from_routed(actor, &routed);
            request.now = now;
            let decision = self.evaluator.evaluate(&request, approval);
            self.evaluator
                .record_decision(journal, run_id, step.step_id(), &request, &decision)?;

            let diagnostic = StepPolicyDiagnostic {
                reason: decision.reason.clone(),
                policy_version: request.policy_version.clone(),
                parameter_hash: request.parameter_hash.clone(),
                authoritative_risk: request.risk,
                planner_risk_hints,
            };

            match decision.kind {
                PolicyDecisionKind::Allow => {
                    let lease = self
                        .evaluator
                        .acquire_lease(&request, &decision)
                        .map_err(StepPolicyError::Lease)?;
                    ensure_no_secret("lease", &lease.to_json())?;
                    Ok(StepPolicyOutcome {
                        kind: StepPolicyOutcomeKind::Allowed,
                        run_id: run_id.to_string(),
                        step_id: step.step_id().to_string(),
                        routed: Some(routed),
                        request: Some(request),
                        decision,
                        lease: Some(lease),
                        diagnostic,
                    })
                }
                PolicyDecisionKind::Deny => Ok(StepPolicyOutcome {
                    kind: StepPolicyOutcomeKind::Denied,
                    run_id: run_id.to_string(),
                    step_id: step.step_id().to_string(),
                    routed: Some(routed),
                    request: Some(request),
                    decision,
                    lease: None,
                    diagnostic,
                }),
                PolicyDecisionKind::PauseForApproval => Ok(StepPolicyOutcome {
                    kind: StepPolicyOutcomeKind::AwaitingApproval,
                    run_id: run_id.to_string(),
                    step_id: step.step_id().to_string(),
                    routed: Some(routed),
                    request: Some(request),
                    decision,
                    lease: None,
                    diagnostic,
                }),
            }
        }

        fn route_denial(
            &self,
            journal: &AuditJournal,
            run_id: &str,
            actor: &str,
            step: &impl ExecutionStep,
            rejection: ToolRejection,
            planner_risk_hints: Vec<RiskClass>,
        ) -> Result<StepPolicyOutcome, StepPolicyError> {
            ensure_no_secret("route_rejection", &rejection.reason)?;
            let parameter_hash = stable_call_hash(step);
            let decision = PolicyDecision {
                kind: PolicyDecisionKind::Deny,
                risk: RiskClass::Never,
                reason: format!(
                    "tool routing denied before policy lease: {}",
                    rejection.reason
                ),
            };
            let diagnostic = StepPolicyDiagnostic {
                reason: decision.reason.clone(),
                policy_version: "policy-v1".to_string(),
                parameter_hash: parameter_hash.clone(),
                authoritative_risk: RiskClass::Never,
                planner_risk_hints,
            };
            let mut event = AuditEvent::new(
                AuditEventType::PolicyEvaluated,
                run_id,
                step.step_id(),
                actor,
                format!(
                    "decision={} tool={} risk={} reason={}",
                    decision.kind.as_str(),
                    step.call().name,
                    decision.risk.as_str(),
                    decision.reason
                ),
            );
            event.policy_version = diagnostic.policy_version.clone();
            event.tool_version = "tool-router-v1".to_string();
            event.parameter_hash = parameter_hash;
            journal.append(&event)?;

            Ok(StepPolicyOutcome {
                kind: StepPolicyOutcomeKind::Denied,
                run_id: run_id.to_string(),
                step_id: step.step_id().to_string(),
                routed: None,
                request: None,
                decision,
                lease: None,
                diagnostic,
            })
        }
    }

    fn policy_request_json(request: &PolicyRequest) -> String {
        format!(
            "{{\"actor\":\"{}\",\"tool\":\"{}\",\"resource\":\"{}\",\"risk\":\"{}\",\"parameter_hash\":\"{}\",\"policy_version\":\"{}\",\"now\":{}}}",
            escape_json(&request.actor),
            escape_json(&request.tool),
            escape_json(&request.resource),
            request.risk.as_str(),
            escape_json(&request.parameter_hash),
            escape_json(&request.policy_version),
            request.now
        )
    }

    fn stable_call_hash(step: &impl ExecutionStep) -> String {
        let mut params = step.call().params.clone();
        params.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        stable_parameter_hash(&params)
    }

    fn ensure_no_secret(field: impl Into<String>, value: &str) -> Result<(), StepPolicyError> {
        if contains_secret_value(value) {
            return Err(StepPolicyError::SecretValue {
                field: field.into(),
            });
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::agent_core::model::{
            ApprovalRequirement, PlanStep, RiskHint, RollbackRequirement, VerificationRule,
        };
        use crate::api::SemanticToolCall;
        use crate::audit::extract_json_string_for_tests;

        fn test_journal(name: &str) -> AuditJournal {
            let path = std::env::temp_dir().join(format!(
                "agentd-policy-adapter-{name}-{}.jsonl",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            AuditJournal::new(path)
        }

        fn adapter() -> PlanStepPolicyAdapter {
            PlanStepPolicyAdapter::new(ToolRouter, PolicyEvaluator)
        }

        fn step(
            step_id: &str,
            tool: &str,
            params: Vec<(&str, &str)>,
            hint: RiskClass,
            approval_required: bool,
        ) -> PlanStep {
            let approval = if approval_required {
                ApprovalRequirement::operator_required("operator approval required")
                    .expect("approval")
            } else {
                ApprovalRequirement::not_required("planner says no approval").expect("approval")
            };
            let rollback = if tool == "fs.write.diff" {
                RollbackRequirement::new(
                    true,
                    Some(format!("rollback-{step_id}")),
                    "write is rollback protected",
                )
                .expect("rollback")
            } else {
                RollbackRequirement::not_required("no rollback required").expect("rollback")
            };
            PlanStep::new(
                step_id,
                SemanticToolCall::new(tool, params),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                VerificationRule::new(format!("verify-{step_id}"), "verification rule", tool)
                    .expect("verification"),
                approval,
                1,
                vec![RiskHint::new(hint, "planner risk hint").expect("risk hint")],
                rollback,
            )
            .expect("plan step")
        }

        fn exact_approval_for(outcome: &StepPolicyOutcome) -> ApprovalToken {
            let request = outcome.request.as_ref().expect("request");
            ApprovalToken {
                actor: request.actor.clone(),
                tool: request.tool.clone(),
                resource: request.resource.clone(),
                parameter_hash: request.parameter_hash.clone(),
                expires_at: request.now + 60,
                policy_version: request.policy_version.clone(),
            }
        }

        #[test]
        fn planner_risk_hints_cannot_downgrade_policy_risk() {
            let journal = test_journal("risk-hint");
            let restart = step(
                "restart-nginx",
                "svc.restart",
                vec![("service", "nginx")],
                RiskClass::ReadOnly,
                false,
            );

            let outcome = adapter()
                .evaluate_step(&journal, "run-policy", "operator", &restart, None)
                .expect("evaluate");

            assert_eq!(outcome.kind, StepPolicyOutcomeKind::AwaitingApproval);
            let request = outcome.request.expect("request");
            assert_eq!(request.risk, RiskClass::ExecuteWithConfirmation);
            assert_eq!(outcome.decision.risk, RiskClass::ExecuteWithConfirmation);
            assert_eq!(
                outcome.diagnostic.planner_risk_hints,
                vec![RiskClass::ReadOnly]
            );
            let lines = journal.event_lines().expect("journal");
            assert!(lines.iter().any(|line| line.contains("PolicyEvaluated")));
            assert!(!lines.iter().any(|line| line.contains("EffectPrepared")));
        }

        #[test]
        fn shell_exec_and_unknown_tools_are_denied_before_effect_preparation() {
            let journal = test_journal("route-deny");
            let shell = step(
                "shell",
                "shell.exec",
                vec![("cmd", "id")],
                RiskClass::ReadOnly,
                false,
            );
            let unknown = step(
                "unknown",
                "unknown.tool",
                vec![("service", "nginx")],
                RiskClass::ReadOnly,
                false,
            );

            let shell_outcome = adapter()
                .evaluate_step(&journal, "run-route", "operator", &shell, None)
                .expect("shell route denial");
            let unknown_outcome = adapter()
                .evaluate_step(&journal, "run-route", "operator", &unknown, None)
                .expect("unknown route denial");

            assert_eq!(shell_outcome.kind, StepPolicyOutcomeKind::Denied);
            assert_eq!(unknown_outcome.kind, StepPolicyOutcomeKind::Denied);
            assert!(shell_outcome.lease.is_none());
            assert!(unknown_outcome.lease.is_none());
            assert!(shell_outcome.routed.is_none());
            assert!(unknown_outcome.routed.is_none());
            let lines = journal.event_lines().expect("journal");
            assert_eq!(
                lines
                    .iter()
                    .filter(|line| line.contains("PolicyEvaluated"))
                    .count(),
                2
            );
            assert!(!lines.iter().any(|line| line.contains("EffectPrepared")));
        }

        #[test]
        fn paused_steps_return_awaiting_approval_without_lease_or_effect() {
            let journal = test_journal("pause");
            let restart = step(
                "restart-nginx",
                "svc.restart",
                vec![("service", "nginx")],
                RiskClass::ExecuteWithConfirmation,
                true,
            );

            let outcome = adapter()
                .evaluate_step(&journal, "run-pause", "operator", &restart, None)
                .expect("evaluate");

            assert_eq!(outcome.kind, StepPolicyOutcomeKind::AwaitingApproval);
            assert_eq!(outcome.decision.kind, PolicyDecisionKind::PauseForApproval);
            assert!(outcome.lease.is_none());
            assert!(outcome.diagnostic.reason.contains("approval token"));
            let lines = journal.event_lines().expect("journal");
            assert_eq!(lines.len(), 1);
            assert!(lines[0].contains("\"event_type\":\"PolicyEvaluated\""));
            assert!(lines[0].contains("pause-for-approval"));
            assert!(!lines[0].contains("EffectPrepared"));
        }

        #[test]
        fn approval_parameter_mutation_is_paused_not_allowed() {
            let initial_journal = test_journal("approval-initial");
            let restart_nginx = step(
                "restart-nginx",
                "svc.restart",
                vec![("service", "nginx")],
                RiskClass::ExecuteWithConfirmation,
                true,
            );
            let initial = adapter()
                .evaluate_step(
                    &initial_journal,
                    "run-approval",
                    "operator",
                    &restart_nginx,
                    None,
                )
                .expect("initial pause");
            let token = exact_approval_for(&initial);

            let mutation_journal = test_journal("approval-mutation");
            let restart_apache = step(
                "restart-apache",
                "svc.restart",
                vec![("service", "apache")],
                RiskClass::ExecuteWithConfirmation,
                true,
            );
            let mutated = adapter()
                .evaluate_step(
                    &mutation_journal,
                    "run-approval",
                    "operator",
                    &restart_apache,
                    Some(&token),
                )
                .expect("mutated approval rejected");

            assert_eq!(mutated.kind, StepPolicyOutcomeKind::AwaitingApproval);
            assert_eq!(mutated.decision.kind, PolicyDecisionKind::PauseForApproval);
            assert!(mutated.lease.is_none());
            assert_ne!(
                token.parameter_hash,
                mutated.request.as_ref().expect("request").parameter_hash
            );
            assert!(!mutation_journal
                .event_lines()
                .expect("journal")
                .iter()
                .any(|line| line.contains("EffectPrepared")));
        }

        #[test]
        fn exact_approval_allows_high_risk_step_and_issues_lease() {
            let initial_journal = test_journal("approval-exact-initial");
            let restart = step(
                "restart-nginx",
                "svc.restart",
                vec![("service", "nginx")],
                RiskClass::ExecuteWithConfirmation,
                true,
            );
            let initial = adapter()
                .evaluate_step(&initial_journal, "run-exact", "operator", &restart, None)
                .expect("initial pause");
            let token = exact_approval_for(&initial);

            let approval_journal = test_journal("approval-exact");
            let allowed = adapter()
                .evaluate_step(
                    &approval_journal,
                    "run-exact",
                    "operator",
                    &restart,
                    Some(&token),
                )
                .expect("approved step");

            assert_eq!(allowed.kind, StepPolicyOutcomeKind::Allowed);
            let lease = allowed.lease.expect("lease");
            let request = allowed.request.expect("request");
            assert_eq!(lease.tool, "svc.restart");
            assert_eq!(lease.resource, "nginx");
            assert_eq!(lease.parameter_hash, request.parameter_hash);
            assert_eq!(lease.policy_version, "policy-v1");
            assert_eq!(lease.risk, RiskClass::ExecuteWithConfirmation);
        }

        #[test]
        fn allowed_read_only_step_receives_sandbox_ready_lease_and_audit_metadata() {
            let journal = test_journal("read-only");
            let status = step(
                "status-nginx",
                "svc.status",
                vec![("service", "nginx")],
                RiskClass::ReadOnly,
                false,
            );

            let outcome = adapter()
                .evaluate_step(&journal, "run-read", "operator", &status, None)
                .expect("evaluate");

            assert_eq!(outcome.kind, StepPolicyOutcomeKind::Allowed);
            let lease = outcome.lease.as_ref().expect("lease");
            let request = outcome.request.as_ref().expect("request");
            assert_eq!(lease.tool, "svc.status");
            assert_eq!(lease.resource, "nginx");
            assert_eq!(lease.parameter_hash, request.parameter_hash);
            assert_eq!(lease.policy_version, request.policy_version);
            assert_eq!(lease.risk, RiskClass::ReadOnly);

            let lines = journal.event_lines().expect("journal");
            assert_eq!(lines.len(), 1);
            assert!(lines[0].contains("\"event_type\":\"PolicyEvaluated\""));
            assert_eq!(
                extract_json_string_for_tests(&lines[0], "policy_version").as_deref(),
                Some("policy-v1")
            );
            assert_eq!(
                extract_json_string_for_tests(&lines[0], "parameter_hash").as_deref(),
                Some(request.parameter_hash.as_str())
            );
            assert!(!lines[0].contains("EffectPrepared"));
            assert!(outcome.to_json().contains("\"kind\":\"allowed\""));
        }
    }
}

pub mod sandbox_profile {
    use std::fmt;

    use crate::agent_core::model::contains_secret_value;
    use crate::api::{escape_json, RiskClass};
    use crate::policy::CapabilityLease;
    use crate::sandbox::{SandboxCompiler, SandboxError, SandboxProfile};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SandboxProfileClass {
        ReadOnlyDiagnostic,
        WriteWithDiffPreparation,
        ExecuteWithConfirmation,
        PrivilegedHumanApproval,
        FirecrackerExecutor,
        Never,
    }

    impl SandboxProfileClass {
        pub fn for_risk(risk: RiskClass) -> Self {
            match risk {
                RiskClass::ReadOnly => Self::ReadOnlyDiagnostic,
                RiskClass::WriteWithDiff => Self::WriteWithDiffPreparation,
                RiskClass::ExecuteWithConfirmation => Self::ExecuteWithConfirmation,
                RiskClass::PrivilegedWithHumanApproval => Self::PrivilegedHumanApproval,
                RiskClass::Never => Self::Never,
            }
        }

        pub fn as_str(self) -> &'static str {
            match self {
                Self::ReadOnlyDiagnostic => "read-only-diagnostic",
                Self::WriteWithDiffPreparation => "write-with-diff-preparation",
                Self::ExecuteWithConfirmation => "execute-with-confirmation",
                Self::PrivilegedHumanApproval => "privileged-human-approval",
                Self::FirecrackerExecutor => "firecracker-executor",
                Self::Never => "never",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct PlannerSandboxHints {
        pub requested_profile_name: Option<String>,
        pub requested_writable_host_paths: Vec<String>,
        pub requested_network_allowlist: Vec<String>,
        pub requested_persistent_write: bool,
    }

    impl PlannerSandboxHints {
        pub fn to_json(&self) -> String {
            format!(
                "{{\"requested_profile_name\":{},\"requested_writable_host_paths\":{},\"requested_network_allowlist\":{},\"requested_persistent_write\":{}}}",
                optional_string_json(self.requested_profile_name.as_deref()),
                string_array_json(&self.requested_writable_host_paths),
                string_array_json(&self.requested_network_allowlist),
                self.requested_persistent_write
            )
        }

        fn ignored_reasons(&self) -> Vec<String> {
            let mut reasons = Vec::new();
            if let Some(name) = &self.requested_profile_name {
                reasons.push(format!("profile_name={name} ignored"));
            }
            if !self.requested_writable_host_paths.is_empty() {
                reasons.push(format!(
                    "writable_host_paths={} ignored",
                    self.requested_writable_host_paths.join("|")
                ));
            }
            if !self.requested_network_allowlist.is_empty() {
                reasons.push(format!(
                    "network_allowlist={} ignored",
                    self.requested_network_allowlist.join("|")
                ));
            }
            if self.requested_persistent_write {
                reasons.push("persistent_write=true ignored".to_string());
            }
            reasons
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FirecrackerDependencyProbe {
        pub kvm_available: bool,
        pub firecracker_binary_available: bool,
        pub jailer_binary_available: bool,
        pub kernel_image_available: bool,
        pub rootfs_image_available: bool,
    }

    impl FirecrackerDependencyProbe {
        pub fn ready() -> Self {
            Self {
                kvm_available: true,
                firecracker_binary_available: true,
                jailer_binary_available: true,
                kernel_image_available: true,
                rootfs_image_available: true,
            }
        }

        pub fn missing_dependencies(&self) -> Vec<String> {
            let mut missing = Vec::new();
            if !self.kvm_available {
                missing.push("kvm".to_string());
            }
            if !self.firecracker_binary_available {
                missing.push("firecracker-binary".to_string());
            }
            if !self.jailer_binary_available {
                missing.push("jailer-binary".to_string());
            }
            if !self.kernel_image_available {
                missing.push("kernel-image".to_string());
            }
            if !self.rootfs_image_available {
                missing.push("rootfs-image".to_string());
            }
            missing
        }

        pub fn to_json(&self) -> String {
            format!(
                "{{\"kvm_available\":{},\"firecracker_binary_available\":{},\"jailer_binary_available\":{},\"kernel_image_available\":{},\"rootfs_image_available\":{}}}",
                self.kvm_available,
                self.firecracker_binary_available,
                self.jailer_binary_available,
                self.kernel_image_available,
                self.rootfs_image_available
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FirecrackerProfileRequest {
        pub firecracker_binary: String,
        pub jailer_binary: String,
        pub kernel_image: String,
        pub rootfs_image: String,
        pub network_mode: String,
        pub block_devices: Vec<String>,
        pub cpu_count: u8,
        pub memory_mib: u32,
        pub rate_limiter: String,
        pub snapshot_policy: String,
        pub dependency_probe: FirecrackerDependencyProbe,
    }

    impl FirecrackerProfileRequest {
        pub fn to_json(&self) -> String {
            format!(
                "{{\"firecracker_binary\":\"{}\",\"jailer_binary\":\"{}\",\"kernel_image\":\"{}\",\"rootfs_image\":\"{}\",\"network_mode\":\"{}\",\"block_devices\":{},\"cpu_count\":{},\"memory_mib\":{},\"rate_limiter\":\"{}\",\"snapshot_policy\":\"{}\",\"dependency_probe\":{}}}",
                escape_json(&self.firecracker_binary),
                escape_json(&self.jailer_binary),
                escape_json(&self.kernel_image),
                escape_json(&self.rootfs_image),
                escape_json(&self.network_mode),
                string_array_json(&self.block_devices),
                self.cpu_count,
                self.memory_mib,
                escape_json(&self.rate_limiter),
                escape_json(&self.snapshot_policy),
                self.dependency_probe.to_json()
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FirecrackerExecutorProfile {
        pub lease_id: String,
        pub tool: String,
        pub resource: String,
        pub parameter_hash: String,
        pub policy_version: String,
        pub risk: RiskClass,
        pub firecracker_binary: String,
        pub jailer_binary: String,
        pub kernel_image: String,
        pub rootfs_image: String,
        pub network_mode: String,
        pub block_devices: Vec<String>,
        pub cpu_count: u8,
        pub memory_mib: u32,
        pub rate_limiter: String,
        pub snapshot_policy: String,
        pub jailer_enabled: bool,
    }

    impl FirecrackerExecutorProfile {
        pub fn to_json(&self) -> String {
            format!(
                "{{\"lease_id\":\"{}\",\"tool\":\"{}\",\"resource\":\"{}\",\"parameter_hash\":\"{}\",\"policy_version\":\"{}\",\"risk\":\"{}\",\"firecracker_binary\":\"{}\",\"jailer_binary\":\"{}\",\"kernel_image\":\"{}\",\"rootfs_image\":\"{}\",\"network_mode\":\"{}\",\"block_devices\":{},\"cpu_count\":{},\"memory_mib\":{},\"rate_limiter\":\"{}\",\"snapshot_policy\":\"{}\",\"jailer_enabled\":{}}}",
                escape_json(&self.lease_id),
                escape_json(&self.tool),
                escape_json(&self.resource),
                escape_json(&self.parameter_hash),
                escape_json(&self.policy_version),
                self.risk.as_str(),
                escape_json(&self.firecracker_binary),
                escape_json(&self.jailer_binary),
                escape_json(&self.kernel_image),
                escape_json(&self.rootfs_image),
                escape_json(&self.network_mode),
                string_array_json(&self.block_devices),
                self.cpu_count,
                self.memory_mib,
                escape_json(&self.rate_limiter),
                escape_json(&self.snapshot_policy),
                self.jailer_enabled
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FirecrackerProfileBinding {
        pub class: SandboxProfileClass,
        pub profile: FirecrackerExecutorProfile,
        pub ignored_planner_hints: Vec<String>,
        pub audit_summary: String,
    }

    impl FirecrackerProfileBinding {
        pub fn to_json(&self) -> String {
            format!(
                "{{\"class\":\"{}\",\"profile\":{},\"ignored_planner_hints\":{},\"audit_summary\":\"{}\"}}",
                self.class.as_str(),
                self.profile.to_json(),
                string_array_json(&self.ignored_planner_hints),
                escape_json(&self.audit_summary)
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SandboxProfileBinding {
        pub class: SandboxProfileClass,
        pub profile: SandboxProfile,
        pub ignored_planner_hints: Vec<String>,
        pub audit_summary: String,
    }

    impl SandboxProfileBinding {
        pub fn to_json(&self) -> String {
            format!(
                "{{\"class\":\"{}\",\"profile\":{},\"ignored_planner_hints\":{},\"audit_summary\":\"{}\"}}",
                self.class.as_str(),
                self.profile.to_json(),
                string_array_json(&self.ignored_planner_hints),
                escape_json(&self.audit_summary)
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SandboxProfileError {
        UnsupportedClass {
            class: SandboxProfileClass,
            reason: String,
        },
        SecretValue {
            field: String,
        },
        InvalidProfile {
            reason: String,
        },
    }

    impl SandboxProfileError {
        pub fn reason(&self) -> String {
            match self {
                SandboxProfileError::UnsupportedClass { class, reason } => {
                    format!(
                        "sandbox profile class {} is unsupported: {reason}",
                        class.as_str()
                    )
                }
                SandboxProfileError::SecretValue { field } => {
                    format!("secret-like value is not allowed in {field}")
                }
                SandboxProfileError::InvalidProfile { reason } => reason.clone(),
            }
        }
    }

    impl fmt::Display for SandboxProfileError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.reason())
        }
    }

    impl From<SandboxError> for SandboxProfileError {
        fn from(value: SandboxError) -> Self {
            match value {
                SandboxError::UnsupportedRisk(risk) => SandboxProfileError::UnsupportedClass {
                    class: SandboxProfileClass::for_risk(risk),
                    reason: value.reason(),
                },
                SandboxError::EmptyResource => SandboxProfileError::InvalidProfile {
                    reason: value.reason(),
                },
            }
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct LeaseSandboxProfileCompiler {
        compiler: SandboxCompiler,
    }

    impl LeaseSandboxProfileCompiler {
        pub fn new(compiler: SandboxCompiler) -> Self {
            Self { compiler }
        }

        pub fn compile(
            &self,
            lease: &CapabilityLease,
            planner_hints: Option<&PlannerSandboxHints>,
        ) -> Result<SandboxProfileBinding, SandboxProfileError> {
            ensure_no_secret("lease", &lease.to_json())?;
            if let Some(hints) = planner_hints {
                ensure_no_secret("planner_sandbox_hints", &hints.to_json())?;
            }

            let class = SandboxProfileClass::for_risk(lease.risk);
            let profile = self.compiler.compile(lease)?;
            self.validate_profile_is_lease_derived(lease, &profile)?;
            let ignored_planner_hints = planner_hints
                .map(PlannerSandboxHints::ignored_reasons)
                .unwrap_or_default();
            let audit_summary = profile_audit_summary(class, &profile, &ignored_planner_hints);
            ensure_no_secret("sandbox_profile_audit_summary", &audit_summary)?;
            Ok(SandboxProfileBinding {
                class,
                profile,
                ignored_planner_hints,
                audit_summary,
            })
        }

        fn validate_profile_is_lease_derived(
            &self,
            lease: &CapabilityLease,
            profile: &SandboxProfile,
        ) -> Result<(), SandboxProfileError> {
            if profile.lease_id != lease.lease_id
                || profile.tool != lease.tool
                || profile.resource != lease.resource
                || profile.parameter_hash != lease.parameter_hash
                || profile.policy_version != lease.policy_version
                || profile.risk != lease.risk
            {
                return Err(SandboxProfileError::InvalidProfile {
                    reason: "sandbox profile metadata must match capability lease".to_string(),
                });
            }
            ensure_no_secret("sandbox_profile", &profile.to_json())?;
            Ok(())
        }

        pub fn compile_firecracker(
            &self,
            lease: &CapabilityLease,
            request: &FirecrackerProfileRequest,
            planner_hints: Option<&PlannerSandboxHints>,
        ) -> Result<FirecrackerProfileBinding, SandboxProfileError> {
            ensure_no_secret("lease", &lease.to_json())?;
            ensure_no_secret("firecracker_profile_request", &request.to_json())?;
            if let Some(hints) = planner_hints {
                ensure_no_secret("planner_sandbox_hints", &hints.to_json())?;
            }

            if !matches!(
                lease.risk,
                RiskClass::ExecuteWithConfirmation | RiskClass::PrivilegedWithHumanApproval
            ) {
                return Err(SandboxProfileError::UnsupportedClass {
                    class: SandboxProfileClass::FirecrackerExecutor,
                    reason: format!(
                        "firecracker executor requires an approved high-risk lease, got {}",
                        lease.risk.as_str()
                    ),
                });
            }

            let missing = request.dependency_probe.missing_dependencies();
            if !missing.is_empty() {
                return Err(SandboxProfileError::InvalidProfile {
                    reason: format!(
                        "firecracker dependencies missing: {}; no host fallback is allowed",
                        missing.join("|")
                    ),
                });
            }
            validate_firecracker_request(request)?;

            let ignored_planner_hints = planner_hints
                .map(PlannerSandboxHints::ignored_reasons)
                .unwrap_or_default();
            let profile = FirecrackerExecutorProfile {
                lease_id: lease.lease_id.clone(),
                tool: lease.tool.clone(),
                resource: lease.resource.clone(),
                parameter_hash: lease.parameter_hash.clone(),
                policy_version: lease.policy_version.clone(),
                risk: lease.risk,
                firecracker_binary: request.firecracker_binary.clone(),
                jailer_binary: request.jailer_binary.clone(),
                kernel_image: request.kernel_image.clone(),
                rootfs_image: request.rootfs_image.clone(),
                network_mode: request.network_mode.clone(),
                block_devices: request.block_devices.clone(),
                cpu_count: request.cpu_count,
                memory_mib: request.memory_mib,
                rate_limiter: request.rate_limiter.clone(),
                snapshot_policy: request.snapshot_policy.clone(),
                jailer_enabled: true,
            };
            ensure_no_secret("firecracker_profile", &profile.to_json())?;
            let audit_summary = firecracker_profile_audit_summary(&profile, &ignored_planner_hints);
            ensure_no_secret("firecracker_profile_audit_summary", &audit_summary)?;
            Ok(FirecrackerProfileBinding {
                class: SandboxProfileClass::FirecrackerExecutor,
                profile,
                ignored_planner_hints,
                audit_summary,
            })
        }
    }

    fn profile_audit_summary(
        class: SandboxProfileClass,
        profile: &SandboxProfile,
        ignored_planner_hints: &[String],
    ) -> String {
        format!(
            "sandbox_profile class={} name={} lease_id={} tool={} risk={} no_new_privs={} namespaces=user:{},mount:{},pid:{},network:{},cgroup:{} cgroup=pids_max:{},memory_max_bytes:{} seccomp=default:{},denied:{} filesystem=persistent_write_allowed:{},read_only_binds:{},writable_tmpfs:{} landlock=enabled:{},read_paths:{},write_paths:{} network=allow:{},allowlist:{} ignored_planner_hints={}",
            class.as_str(),
            profile.name,
            profile.lease_id,
            profile.tool,
            profile.risk.as_str(),
            profile.no_new_privs,
            profile.namespaces.user,
            profile.namespaces.mount,
            profile.namespaces.pid,
            profile.namespaces.network,
            profile.namespaces.cgroup,
            profile.cgroup.pids_max,
            profile.cgroup.memory_max_bytes,
            profile.seccomp.default_action,
            profile.seccomp.denied_syscalls.join("|"),
            profile.filesystem.persistent_write_allowed,
            profile.filesystem.read_only_binds.len(),
            profile.filesystem.writable_tmpfs.join("|"),
            profile.landlock.enabled_when_supported,
            profile.landlock.allowed_read_paths.join("|"),
            profile.landlock.allowed_write_paths.join("|"),
            profile.network.allow_network,
            profile.network.allowlist.join("|"),
            ignored_planner_hints.len()
        )
    }

    fn validate_firecracker_request(
        request: &FirecrackerProfileRequest,
    ) -> Result<(), SandboxProfileError> {
        for (field, value) in [
            ("firecracker_binary", request.firecracker_binary.as_str()),
            ("jailer_binary", request.jailer_binary.as_str()),
            ("kernel_image", request.kernel_image.as_str()),
            ("rootfs_image", request.rootfs_image.as_str()),
            ("network_mode", request.network_mode.as_str()),
            ("rate_limiter", request.rate_limiter.as_str()),
            ("snapshot_policy", request.snapshot_policy.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(SandboxProfileError::InvalidProfile {
                    reason: format!("firecracker profile requires {field}"),
                });
            }
        }
        if request.cpu_count == 0 {
            return Err(SandboxProfileError::InvalidProfile {
                reason: "firecracker profile requires at least one vCPU".to_string(),
            });
        }
        if request.memory_mib < 128 {
            return Err(SandboxProfileError::InvalidProfile {
                reason: "firecracker profile requires at least 128 MiB memory".to_string(),
            });
        }
        if !matches!(request.network_mode.as_str(), "none" | "tap" | "restricted") {
            return Err(SandboxProfileError::InvalidProfile {
                reason: "firecracker network mode must be none, tap, or restricted".to_string(),
            });
        }
        if !matches!(
            request.snapshot_policy.as_str(),
            "disabled" | "same-host-only"
        ) {
            return Err(SandboxProfileError::InvalidProfile {
                reason: "firecracker snapshot policy must be disabled or same-host-only"
                    .to_string(),
            });
        }
        Ok(())
    }

    fn firecracker_profile_audit_summary(
        profile: &FirecrackerExecutorProfile,
        ignored_planner_hints: &[String],
    ) -> String {
        format!(
            "firecracker_profile class={} lease_id={} tool={} risk={} kernel_image={} rootfs_image={} network_mode={} block_devices={} cpu_count={} memory_mib={} rate_limiter={} snapshot_policy={} jailer_enabled={} host_trust=same-host-trusted snapshot_trust=not-portable ignored_planner_hints={}",
            SandboxProfileClass::FirecrackerExecutor.as_str(),
            profile.lease_id,
            profile.tool,
            profile.risk.as_str(),
            profile.kernel_image,
            profile.rootfs_image,
            profile.network_mode,
            profile.block_devices.join("|"),
            profile.cpu_count,
            profile.memory_mib,
            profile.rate_limiter,
            profile.snapshot_policy,
            profile.jailer_enabled,
            ignored_planner_hints.len()
        )
    }

    fn ensure_no_secret(field: impl Into<String>, value: &str) -> Result<(), SandboxProfileError> {
        if contains_secret_value(value) {
            return Err(SandboxProfileError::SecretValue {
                field: field.into(),
            });
        }
        Ok(())
    }

    fn optional_string_json(value: Option<&str>) -> String {
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
        use super::*;
        use crate::audit::AuditJournal;
        use crate::policy::{stable_parameter_hash, PolicyDecision, PolicyDecisionKind};
        use crate::sandbox::{SandboxDecision, SandboxExecutor, SandboxOperation};
        use crate::security_execution::effect_envelope::{EffectEnvelope, EffectEnvelopeState};

        fn lease_for(
            tool: &str,
            resource: &str,
            risk: RiskClass,
            params: Vec<(&str, &str)>,
        ) -> CapabilityLease {
            let normalized_params = params
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<Vec<_>>();
            CapabilityLease {
                lease_id: format!("lease-{tool}-{}", stable_parameter_hash(&normalized_params)),
                actor: "operator".to_string(),
                tool: tool.to_string(),
                resource: resource.to_string(),
                parameter_hash: stable_parameter_hash(&normalized_params),
                expires_at: 60,
                policy_version: "policy-v1".to_string(),
                risk,
            }
        }

        fn compiler() -> LeaseSandboxProfileCompiler {
            LeaseSandboxProfileCompiler::new(SandboxCompiler)
        }

        fn test_journal(name: &str) -> AuditJournal {
            let path = std::env::temp_dir().join(format!(
                "agentd-sandbox-profile-{name}-{}.jsonl",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            AuditJournal::new(path)
        }

        fn allow_decision(risk: RiskClass) -> PolicyDecision {
            PolicyDecision {
                kind: PolicyDecisionKind::Allow,
                risk,
                reason: "allowed by policy adapter".to_string(),
            }
        }

        fn firecracker_request() -> FirecrackerProfileRequest {
            FirecrackerProfileRequest {
                firecracker_binary: "/usr/bin/firecracker".to_string(),
                jailer_binary: "/usr/bin/jailer".to_string(),
                kernel_image: "/var/lib/agentos/firecracker/vmlinux".to_string(),
                rootfs_image: "/var/lib/agentos/firecracker/rootfs.ext4".to_string(),
                network_mode: "restricted".to_string(),
                block_devices: vec!["rootfs:ro".to_string()],
                cpu_count: 2,
                memory_mib: 512,
                rate_limiter: "default-deny-egress".to_string(),
                snapshot_policy: "same-host-only".to_string(),
                dependency_probe: FirecrackerDependencyProbe::ready(),
            }
        }

        #[test]
        fn read_only_lease_compiles_without_persistent_write_access() {
            let lease = lease_for(
                "fs.read",
                "/var/log/agentd.log",
                RiskClass::ReadOnly,
                vec![("path", "/var/log/agentd.log")],
            );
            let hints = PlannerSandboxHints {
                requested_profile_name: Some("host-write-all".to_string()),
                requested_writable_host_paths: vec!["/etc".to_string(), "/".to_string()],
                requested_network_allowlist: vec!["0.0.0.0/0".to_string()],
                requested_persistent_write: true,
            };

            let binding = compiler().compile(&lease, Some(&hints)).expect("profile");

            assert_eq!(binding.class, SandboxProfileClass::ReadOnlyDiagnostic);
            assert_eq!(binding.profile.lease_id, lease.lease_id);
            assert!(!binding.profile.filesystem.persistent_write_allowed);
            assert!(!binding
                .profile
                .filesystem
                .writable_tmpfs
                .iter()
                .any(|path| path == "/etc" || path == "/"));
            assert!(!binding.profile.network.allow_network);
            assert!(binding.profile.network.allowlist.is_empty());
            assert_eq!(binding.ignored_planner_hints.len(), 4);
            assert!(binding
                .audit_summary
                .contains("persistent_write_allowed:false"));
        }

        #[test]
        fn planner_network_hints_cannot_broaden_http_check_allowlist() {
            let lease = lease_for(
                "http.check",
                "https://example.test/health",
                RiskClass::ReadOnly,
                vec![("url", "https://example.test/health")],
            );
            let hints = PlannerSandboxHints {
                requested_network_allowlist: vec![
                    "https://evil.test".to_string(),
                    "0.0.0.0/0".to_string(),
                ],
                ..PlannerSandboxHints::default()
            };

            let binding = compiler().compile(&lease, Some(&hints)).expect("profile");

            assert!(binding.profile.network.allow_network);
            assert_eq!(
                binding.profile.network.allowlist,
                vec!["https://example.test/health".to_string()]
            );
            assert!(!binding
                .profile
                .network
                .allowlist
                .iter()
                .any(|target| target.contains("evil") || target == "0.0.0.0/0"));
            assert_eq!(binding.ignored_planner_hints.len(), 1);
        }

        #[test]
        fn unsupported_risk_classes_fail_closed() {
            for (tool, risk) in [
                ("fs.write.diff", RiskClass::WriteWithDiff),
                ("svc.restart", RiskClass::ExecuteWithConfirmation),
                ("host.privileged", RiskClass::PrivilegedWithHumanApproval),
                ("shell.exec", RiskClass::Never),
            ] {
                let lease = lease_for(tool, tool, risk, vec![("resource", tool)]);
                let error = compiler()
                    .compile(&lease, None)
                    .expect_err("unsupported profile fails closed");
                assert!(error.reason().contains("unsupported"));
                assert!(error
                    .reason()
                    .contains(SandboxProfileClass::for_risk(risk).as_str()));
            }
        }

        #[test]
        fn sandbox_profile_metadata_appears_in_effect_envelope() {
            let lease = lease_for(
                "svc.status",
                "nginx",
                RiskClass::ReadOnly,
                vec![("service", "nginx")],
            );
            let binding = compiler().compile(&lease, None).expect("profile");
            let journal = test_journal("envelope");
            let mut envelope = EffectEnvelope::draft(
                "run-sandbox",
                "status-nginx",
                "svc.status",
                vec![("service".to_string(), "nginx".to_string())],
                allow_decision(RiskClass::ReadOnly),
            )
            .expect("draft");

            envelope
                .prepare(
                    &journal,
                    "operator",
                    lease,
                    Some(binding.profile.clone()),
                    None,
                )
                .expect("prepare");
            assert_eq!(envelope.state, EffectEnvelopeState::Prepared);

            let json = envelope.to_json().expect("serialize");
            assert!(json.contains("\"sandbox_profile\":{"));
            assert!(json.contains("\"no_new_privs\":true"));
            assert!(json.contains("\"allowed_syscalls\""));
            assert!(json.contains("\"denied_syscalls\""));
            assert!(json.contains("\"persistent_write_allowed\":false"));
            assert!(json.contains("\"pids_max\":32"));
            assert!(json.contains("\"allowlist\":[]"));
            assert!(json.contains("\"landlock\""));
        }

        #[test]
        fn resource_abuse_still_hits_configured_limits() {
            let lease = lease_for(
                "svc.status",
                "agentd",
                RiskClass::ReadOnly,
                vec![("service", "agentd")],
            );
            let binding = compiler().compile(&lease, None).expect("profile");
            let report = SandboxExecutor.evaluate(
                &binding.profile,
                SandboxOperation::SpawnProcesses {
                    count: binding.profile.cgroup.pids_max + 1,
                },
            );

            assert_eq!(report.decision, SandboxDecision::Denied);
            assert!(report.reason.contains("pids.max"));
            assert!(binding.audit_summary.contains("pids_max:32"));
        }

        #[test]
        fn binding_projection_contains_profile_audit_metadata() {
            let lease = lease_for(
                "fs.read",
                "/var/log/agentd.log",
                RiskClass::ReadOnly,
                vec![("path", "/var/log/agentd.log")],
            );
            let binding = compiler().compile(&lease, None).expect("profile");
            let json = binding.to_json();

            assert!(json.contains("\"class\":\"read-only-diagnostic\""));
            assert!(json.contains("\"seccomp\""));
            assert!(json.contains("\"writable_tmpfs\""));
            assert!(json.contains("\"allowed_read_paths\""));
            assert!(json.contains("\"audit_summary\""));
            assert!(json.contains("no_new_privs=true"));
        }

        #[test]
        fn firecracker_profile_compiles_from_high_risk_lease() {
            let lease = lease_for(
                "svc.restart",
                "nginx",
                RiskClass::ExecuteWithConfirmation,
                vec![("service", "nginx")],
            );
            let hints = PlannerSandboxHints {
                requested_profile_name: Some("host-profile".to_string()),
                requested_writable_host_paths: vec!["/".to_string()],
                requested_network_allowlist: vec!["0.0.0.0/0".to_string()],
                requested_persistent_write: true,
            };

            let binding = compiler()
                .compile_firecracker(&lease, &firecracker_request(), Some(&hints))
                .expect("firecracker profile");

            assert_eq!(binding.class, SandboxProfileClass::FirecrackerExecutor);
            assert_eq!(binding.profile.lease_id, lease.lease_id);
            assert_eq!(binding.profile.tool, lease.tool);
            assert_eq!(binding.profile.resource, lease.resource);
            assert_eq!(binding.profile.parameter_hash, lease.parameter_hash);
            assert_eq!(binding.profile.risk, RiskClass::ExecuteWithConfirmation);
            assert_eq!(binding.profile.cpu_count, 2);
            assert_eq!(binding.profile.memory_mib, 512);
            assert_eq!(binding.profile.network_mode, "restricted");
            assert_eq!(binding.profile.snapshot_policy, "same-host-only");
            assert!(binding.profile.jailer_enabled);
            assert_eq!(binding.ignored_planner_hints.len(), 4);
            assert!(binding
                .ignored_planner_hints
                .iter()
                .any(|reason| reason.contains("0.0.0.0/0")));
            assert!(!binding
                .profile
                .block_devices
                .iter()
                .any(|device| device == "/"));
            assert!(binding
                .audit_summary
                .contains("snapshot_trust=not-portable"));
            assert!(binding
                .audit_summary
                .contains("host_trust=same-host-trusted"));
            assert!(binding.audit_summary.contains("ignored_planner_hints=4"));
            assert!(!binding.audit_summary.contains("host-profile"));
        }

        #[test]
        fn firecracker_profile_missing_dependencies_fail_closed() {
            let lease = lease_for(
                "svc.restart",
                "nginx",
                RiskClass::ExecuteWithConfirmation,
                vec![("service", "nginx")],
            );
            let mut request = firecracker_request();
            request.dependency_probe.kvm_available = false;
            request.dependency_probe.rootfs_image_available = false;

            let error = compiler()
                .compile_firecracker(&lease, &request, None)
                .expect_err("missing dependencies fail closed");

            assert!(error.reason().contains("firecracker dependencies missing"));
            assert!(error.reason().contains("kvm"));
            assert!(error.reason().contains("rootfs-image"));
            assert!(error.reason().contains("no host fallback"));
        }
    }
}

pub mod engine {
    use std::fmt;
    use std::fs;
    use std::path::PathBuf;

    use crate::agent_core::model::{contains_secret_value, PlanStep};
    use crate::api::{escape_json, CommitId, RiskClass, VerificationResult};
    use crate::audit::AuditJournal;
    use crate::policy::{ApprovalToken, PolicyEvaluator};
    use crate::rollback::{
        content_hash, PreparedWrite, RollbackReport, WriteDiffError, WriteDiffExecutor,
        WriteRequest,
    };
    use crate::sandbox::{
        SandboxCompiler, SandboxDecision, SandboxExecutor, SandboxOperation, SandboxReport,
    };
    use crate::tools::ToolRouter;

    use super::effect_envelope::{EffectEnvelope, EffectEnvelopeError, EffectEnvelopeState};
    use super::policy_adapter::{
        PlanStepPolicyAdapter, StepPolicyError, StepPolicyOutcome, StepPolicyOutcomeKind,
    };
    use super::sandbox_profile::{
        FirecrackerProfileBinding, FirecrackerProfileRequest, LeaseSandboxProfileCompiler,
        PlannerSandboxHints, SandboxProfileBinding, SandboxProfileError,
    };

    pub trait SecurityExecutionEngine {
        fn prepare(
            &self,
            journal: &AuditJournal,
            request: StepExecutionRequest,
        ) -> Result<PreparedStepExecution, SecurityExecutionError>;
        fn execute(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
        ) -> Result<ExecutionReport, SecurityExecutionError>;
        fn observe(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
            report: &ExecutionReport,
        ) -> Result<(), SecurityExecutionError>;
        fn verify(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
            result: VerificationResult,
        ) -> Result<(), SecurityExecutionError>;
        fn seal(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
            commit_id: CommitId,
        ) -> Result<(), SecurityExecutionError>;
        fn rollback(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
            reason: &str,
        ) -> Result<RollbackReport, SecurityExecutionError>;
        fn explain(
            &self,
            prepared: &PreparedStepExecution,
        ) -> Result<String, SecurityExecutionError>;
    }

    #[derive(Debug, Clone)]
    pub struct DefaultSecurityExecutionEngine {
        policy_adapter: PlanStepPolicyAdapter,
        sandbox_compiler: LeaseSandboxProfileCompiler,
        sandbox_executor: SandboxExecutor,
        write_executor: WriteDiffExecutor,
    }

    impl DefaultSecurityExecutionEngine {
        pub fn new(write_shadow_root: impl Into<PathBuf>) -> Self {
            Self {
                policy_adapter: PlanStepPolicyAdapter::new(ToolRouter, PolicyEvaluator),
                sandbox_compiler: LeaseSandboxProfileCompiler::new(SandboxCompiler),
                sandbox_executor: SandboxExecutor,
                write_executor: WriteDiffExecutor::new(write_shadow_root),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct WriteDiffInput {
        pub target_path: PathBuf,
        pub base_hash: String,
        pub proposed_content: String,
    }

    impl WriteDiffInput {
        pub fn new(
            target_path: impl Into<PathBuf>,
            base_hash: impl Into<String>,
            proposed_content: impl Into<String>,
        ) -> Result<Self, SecurityExecutionError> {
            let input = Self {
                target_path: target_path.into(),
                base_hash: base_hash.into(),
                proposed_content: proposed_content.into(),
            };
            ensure_no_secret(
                "write_input.target_path",
                &input.target_path.display().to_string(),
            )?;
            ensure_no_secret("write_input.base_hash", &input.base_hash)?;
            ensure_no_secret("write_input.proposed_content", &input.proposed_content)?;
            Ok(input)
        }
    }

    #[derive(Debug, Clone)]
    pub struct StepExecutionRequest {
        pub run_id: String,
        pub actor: String,
        pub step: PlanStep,
        pub approval: Option<ApprovalToken>,
        pub now: u64,
        pub write_input: Option<WriteDiffInput>,
        pub sandbox_hints: Option<PlannerSandboxHints>,
        pub firecracker_profile: Option<FirecrackerProfileRequest>,
    }

    impl StepExecutionRequest {
        pub fn new(
            run_id: impl Into<String>,
            actor: impl Into<String>,
            step: PlanStep,
        ) -> Result<Self, SecurityExecutionError> {
            let request = Self {
                run_id: run_id.into(),
                actor: actor.into(),
                step,
                approval: None,
                now: 0,
                write_input: None,
                sandbox_hints: None,
                firecracker_profile: None,
            };
            request.validate()?;
            Ok(request)
        }

        pub fn with_approval(mut self, approval: ApprovalToken) -> Self {
            self.approval = Some(approval);
            self
        }

        pub fn at(mut self, now: u64) -> Self {
            self.now = now;
            self
        }

        pub fn with_write_input(mut self, input: WriteDiffInput) -> Self {
            self.write_input = Some(input);
            self
        }

        pub fn with_sandbox_hints(mut self, hints: PlannerSandboxHints) -> Self {
            self.sandbox_hints = Some(hints);
            self
        }

        pub fn with_firecracker_profile(mut self, profile: FirecrackerProfileRequest) -> Self {
            self.firecracker_profile = Some(profile);
            self
        }

        fn validate(&self) -> Result<(), SecurityExecutionError> {
            ensure_no_secret("execution_request.run_id", &self.run_id)?;
            ensure_no_secret("execution_request.actor", &self.actor)?;
            ensure_no_secret("execution_request.step_id", self.step.step_id())?;
            if let Some(approval) = &self.approval {
                ensure_no_secret("execution_request.approval_actor", &approval.actor)?;
                ensure_no_secret("execution_request.approval_tool", &approval.tool)?;
                ensure_no_secret("execution_request.approval_resource", &approval.resource)?;
                ensure_no_secret("execution_request.approval_hash", &approval.parameter_hash)?;
            }
            if let Some(profile) = &self.firecracker_profile {
                ensure_no_secret("execution_request.firecracker_profile", &profile.to_json())?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PreparedExecutionStatus {
        Prepared,
        Denied,
        AwaitingApproval,
    }

    impl PreparedExecutionStatus {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Prepared => "prepared",
                Self::Denied => "denied",
                Self::AwaitingApproval => "awaiting-approval",
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct PreparedStepExecution {
        pub status: PreparedExecutionStatus,
        pub run_id: String,
        pub step_id: String,
        pub actor: String,
        pub outcome: StepPolicyOutcome,
        pub envelope: Option<EffectEnvelope>,
        pub sandbox_binding: Option<SandboxProfileBinding>,
        pub firecracker_binding: Option<FirecrackerProfileBinding>,
        pub prepared_write: Option<PreparedWrite>,
        pub execution_report: Option<ExecutionReport>,
    }

    impl PreparedStepExecution {
        pub fn to_json(&self) -> Result<String, SecurityExecutionError> {
            let envelope = self
                .envelope
                .as_ref()
                .map(EffectEnvelope::to_json)
                .transpose()?
                .unwrap_or_else(|| "null".to_string());
            let sandbox_binding = self
                .sandbox_binding
                .as_ref()
                .map(SandboxProfileBinding::to_json)
                .unwrap_or_else(|| "null".to_string());
            let firecracker_binding = self
                .firecracker_binding
                .as_ref()
                .map(FirecrackerProfileBinding::to_json)
                .unwrap_or_else(|| "null".to_string());
            let rollback_handle = self
                .prepared_write
                .as_ref()
                .map(|prepared| prepared.handle.to_json())
                .unwrap_or_else(|| "null".to_string());
            let execution_report = self
                .execution_report
                .as_ref()
                .map(ExecutionReport::to_json)
                .unwrap_or_else(|| "null".to_string());
            Ok(format!(
                "{{\"status\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"actor\":\"{}\",\"outcome\":{},\"envelope\":{},\"sandbox_binding\":{},\"firecracker_binding\":{},\"rollback_handle\":{},\"execution_report\":{}}}",
                self.status.as_str(),
                escape_json(&self.run_id),
                escape_json(&self.step_id),
                escape_json(&self.actor),
                self.outcome.to_json(),
                envelope,
                sandbox_binding,
                firecracker_binding,
                rollback_handle,
                execution_report
            ))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ExecutionReportKind {
        ReadOnlySandbox,
        WriteWithDiff,
        ControlledEffect,
    }

    impl ExecutionReportKind {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::ReadOnlySandbox => "read-only-sandbox",
                Self::WriteWithDiff => "write-with-diff",
                Self::ControlledEffect => "controlled-effect",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ExecutionReport {
        pub kind: ExecutionReportKind,
        pub tool: String,
        pub success: bool,
        pub summary: String,
        pub sandbox_report: Option<SandboxReport>,
        pub rollback_id: Option<String>,
    }

    impl ExecutionReport {
        pub fn to_json(&self) -> String {
            let sandbox_report = self
                .sandbox_report
                .as_ref()
                .map(SandboxReport::to_json)
                .unwrap_or_else(|| "null".to_string());
            format!(
                "{{\"kind\":\"{}\",\"tool\":\"{}\",\"success\":{},\"summary\":\"{}\",\"sandbox_report\":{},\"rollback_id\":{}}}",
                self.kind.as_str(),
                escape_json(&self.tool),
                self.success,
                escape_json(&self.summary),
                sandbox_report,
                optional_string_json(self.rollback_id.as_deref())
            )
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ExecutionFailureClass {
        Suspended,
        Denied,
        RollbackPending,
        FailedClosed,
    }

    impl ExecutionFailureClass {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Suspended => "Suspended",
                Self::Denied => "Denied",
                Self::RollbackPending => "RollbackPending",
                Self::FailedClosed => "FailedClosed",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SecurityExecutionError {
        Policy(StepPolicyError),
        Effect(EffectEnvelopeError),
        SandboxProfile(SandboxProfileError),
        WriteDiff(WriteDiffError),
        SandboxDenied {
            report: SandboxReport,
        },
        InvalidState {
            action: &'static str,
            reason: String,
        },
        SecretValue {
            field: String,
        },
        Io(String),
    }

    impl SecurityExecutionError {
        pub fn failure_class(&self) -> ExecutionFailureClass {
            match self {
                Self::Policy(_) | Self::SandboxDenied { .. } => ExecutionFailureClass::Denied,
                Self::InvalidState { action, .. } if *action == "prepare-approval" => {
                    ExecutionFailureClass::Suspended
                }
                Self::Effect(error) if error.reason().contains("RollbackPending") => {
                    ExecutionFailureClass::RollbackPending
                }
                Self::WriteDiff(WriteDiffError::BaseHashMismatch { .. }) => {
                    ExecutionFailureClass::RollbackPending
                }
                _ => ExecutionFailureClass::FailedClosed,
            }
        }

        pub fn reason(&self) -> String {
            match self {
                Self::Policy(error) => error.reason(),
                Self::Effect(error) => error.reason(),
                Self::SandboxProfile(error) => error.reason(),
                Self::WriteDiff(error) => error.reason(),
                Self::SandboxDenied { report } => report.reason.clone(),
                Self::InvalidState { action, reason } => {
                    format!("invalid security execution state for {action}: {reason}")
                }
                Self::SecretValue { field } => {
                    format!("secret-like value is not allowed in {field}")
                }
                Self::Io(error) => error.clone(),
            }
        }
    }

    impl fmt::Display for SecurityExecutionError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.reason())
        }
    }

    impl std::error::Error for SecurityExecutionError {}

    impl From<StepPolicyError> for SecurityExecutionError {
        fn from(value: StepPolicyError) -> Self {
            Self::Policy(value)
        }
    }

    impl From<EffectEnvelopeError> for SecurityExecutionError {
        fn from(value: EffectEnvelopeError) -> Self {
            Self::Effect(value)
        }
    }

    impl From<SandboxProfileError> for SecurityExecutionError {
        fn from(value: SandboxProfileError) -> Self {
            Self::SandboxProfile(value)
        }
    }

    impl From<WriteDiffError> for SecurityExecutionError {
        fn from(value: WriteDiffError) -> Self {
            Self::WriteDiff(value)
        }
    }

    impl From<std::io::Error> for SecurityExecutionError {
        fn from(value: std::io::Error) -> Self {
            Self::Io(value.to_string())
        }
    }

    impl SecurityExecutionEngine for DefaultSecurityExecutionEngine {
        fn prepare(
            &self,
            journal: &AuditJournal,
            request: StepExecutionRequest,
        ) -> Result<PreparedStepExecution, SecurityExecutionError> {
            request.validate()?;
            let outcome = self.policy_adapter.evaluate_step_at(
                journal,
                &request.run_id,
                &request.actor,
                &request.step,
                request.approval.as_ref(),
                request.now,
            )?;

            match outcome.kind {
                StepPolicyOutcomeKind::Denied => {
                    return Ok(prepared_without_envelope(
                        PreparedExecutionStatus::Denied,
                        request,
                        outcome,
                    ));
                }
                StepPolicyOutcomeKind::AwaitingApproval => {
                    return Ok(prepared_without_envelope(
                        PreparedExecutionStatus::AwaitingApproval,
                        request,
                        outcome,
                    ));
                }
                StepPolicyOutcomeKind::Allowed => {}
            }

            let routed = outcome.routed.as_ref().ok_or_else(|| {
                invalid("prepare", "allowed policy outcome is missing routed tool")
            })?;
            let lease = outcome.lease.as_ref().ok_or_else(|| {
                invalid(
                    "prepare",
                    "allowed policy outcome is missing capability lease",
                )
            })?;
            let mut envelope = EffectEnvelope::draft(
                &request.run_id,
                request.step.step_id(),
                routed.tool,
                routed.normalized_params.clone(),
                outcome.decision.clone(),
            )?;

            let mut sandbox_binding = None;
            let mut firecracker_binding = None;
            let mut prepared_write = None;
            let mut rollback_handle = None;

            if lease.risk == RiskClass::ReadOnly {
                let binding = self
                    .sandbox_compiler
                    .compile(lease, request.sandbox_hints.as_ref())?;
                sandbox_binding = Some(binding);
            } else if lease.risk == RiskClass::WriteWithDiff {
                if !request.step.rollback().required() {
                    return Err(invalid(
                        "prepare",
                        "write-with-diff steps require a rollback requirement",
                    ));
                }
                let input = request
                    .write_input
                    .as_ref()
                    .ok_or_else(|| invalid("prepare", "write-with-diff requires write input"))?;
                validate_write_input(&request.step, &routed.normalized_params, input)?;
                let write = self.write_executor.prepare(
                    lease,
                    WriteRequest {
                        run_id: request.run_id.clone(),
                        step_id: request.step.step_id().to_string(),
                        actor: request.actor.clone(),
                        target_path: input.target_path.clone(),
                        proposed_content: input.proposed_content.clone(),
                        base_hash: input.base_hash.clone(),
                    },
                )?;
                rollback_handle = Some(write.handle.clone());
                prepared_write = Some(write);
            }

            if let Some(profile_request) = &request.firecracker_profile {
                let binding = self.sandbox_compiler.compile_firecracker(
                    lease,
                    profile_request,
                    request.sandbox_hints.as_ref(),
                )?;
                envelope.set_execution_profile_summary(binding.audit_summary.clone())?;
                firecracker_binding = Some(binding);
            }

            envelope.prepare(
                journal,
                &request.actor,
                lease.clone(),
                sandbox_binding
                    .as_ref()
                    .map(|binding| binding.profile.clone()),
                rollback_handle,
            )?;

            Ok(PreparedStepExecution {
                status: PreparedExecutionStatus::Prepared,
                run_id: request.run_id,
                step_id: request.step.step_id().to_string(),
                actor: request.actor,
                outcome,
                envelope: Some(envelope),
                sandbox_binding,
                firecracker_binding,
                prepared_write,
                execution_report: None,
            })
        }

        fn execute(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
        ) -> Result<ExecutionReport, SecurityExecutionError> {
            let envelope = prepared_envelope(prepared, "execute")?;
            if envelope.state != EffectEnvelopeState::Prepared {
                return Err(invalid("execute", "execute requires a prepared envelope"));
            }
            let lease = prepared
                .outcome
                .lease
                .as_ref()
                .ok_or_else(|| invalid("execute", "prepared execution is missing lease"))?;
            let report = match lease.risk {
                RiskClass::ReadOnly => {
                    let binding = prepared.sandbox_binding.as_ref().ok_or_else(|| {
                        invalid("execute", "read-only execution is missing sandbox binding")
                    })?;
                    let sandbox_report = self.sandbox_executor.evaluate(
                        &binding.profile,
                        sandbox_operation_for(&binding.profile.tool, &binding.profile.resource),
                    );
                    self.sandbox_executor.record_report(
                        journal,
                        prepared.run_id.as_str(),
                        prepared.step_id.as_str(),
                        &sandbox_report,
                    )?;
                    if sandbox_report.decision == SandboxDecision::Denied {
                        return Err(SecurityExecutionError::SandboxDenied {
                            report: sandbox_report,
                        });
                    }
                    ExecutionReport {
                        kind: ExecutionReportKind::ReadOnlySandbox,
                        tool: lease.tool.clone(),
                        success: true,
                        summary: format!("read-only sandbox allowed {}", sandbox_report.reason),
                        sandbox_report: Some(sandbox_report),
                        rollback_id: None,
                    }
                }
                RiskClass::WriteWithDiff => {
                    let write = prepared.prepared_write.as_ref().ok_or_else(|| {
                        invalid(
                            "execute",
                            "write-with-diff execution is missing prepared write",
                        )
                    })?;
                    let proposed = fs::read_to_string(&write.handle.proposed_content_path)?;
                    fs::write(&write.handle.target_path, proposed.as_bytes())?;
                    let final_content = fs::read_to_string(&write.handle.target_path)?;
                    let final_hash = content_hash(&final_content);
                    ExecutionReport {
                        kind: ExecutionReportKind::WriteWithDiff,
                        tool: lease.tool.clone(),
                        success: final_hash == write.handle.proposed_hash,
                        summary: format!(
                            "write-with-diff target={} rollback_id={} final_hash={}",
                            write.handle.target_path.display(),
                            write.handle.rollback_id,
                            final_hash
                        ),
                        sandbox_report: None,
                        rollback_id: Some(write.handle.rollback_id.clone()),
                    }
                }
                RiskClass::ExecuteWithConfirmation | RiskClass::PrivilegedWithHumanApproval => {
                    let summary = if let Some(binding) = &prepared.firecracker_binding {
                        format!(
                            "firecracker controlled effect profile selected class={} lease_id={} tool={} resource={} parameter_hash={} policy_reason={} snapshot_trust=not-portable no_host_fallback=true",
                            binding.class.as_str(),
                            binding.profile.lease_id,
                            lease.tool,
                            lease.resource,
                            lease.parameter_hash,
                            prepared.outcome.decision.reason
                        )
                    } else {
                        format!(
                            "controlled effect executed tool={} resource={} parameter_hash={}",
                            lease.tool, lease.resource, lease.parameter_hash
                        )
                    };
                    ExecutionReport {
                        kind: ExecutionReportKind::ControlledEffect,
                        tool: lease.tool.clone(),
                        success: true,
                        summary,
                        sandbox_report: None,
                        rollback_id: None,
                    }
                }
                RiskClass::Never => {
                    return Err(invalid(
                        "execute",
                        "never-risk execution cannot be prepared",
                    ));
                }
            };
            ensure_no_secret("execution_report", &report.to_json())?;
            prepared.execution_report = Some(report.clone());
            Ok(report)
        }

        fn observe(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
            report: &ExecutionReport,
        ) -> Result<(), SecurityExecutionError> {
            ensure_no_secret("execution_report", &report.to_json())?;
            let actor = prepared.actor.clone();
            let envelope = prepared_envelope_mut(prepared, "observe")?;
            envelope.observe(journal, &actor, report.summary.clone())?;
            Ok(())
        }

        fn verify(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
            result: VerificationResult,
        ) -> Result<(), SecurityExecutionError> {
            let actor = prepared.actor.clone();
            let envelope = prepared_envelope_mut(prepared, "verify")?;
            envelope.verify(journal, &actor, result)?;
            Ok(())
        }

        fn seal(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
            commit_id: CommitId,
        ) -> Result<(), SecurityExecutionError> {
            let actor = prepared.actor.clone();
            let envelope = prepared_envelope_mut(prepared, "seal")?;
            envelope.seal(journal, &actor, commit_id)?;
            Ok(())
        }

        fn rollback(
            &self,
            journal: &AuditJournal,
            prepared: &mut PreparedStepExecution,
            reason: &str,
        ) -> Result<RollbackReport, SecurityExecutionError> {
            ensure_no_secret("rollback_reason", reason)?;
            let actor = prepared.actor.clone();
            let run_id = prepared.run_id.clone();
            let step_id = prepared.step_id.clone();
            let envelope = prepared_envelope_mut(prepared, "rollback")?;
            if envelope.state != EffectEnvelopeState::RollbackPending {
                envelope.mark_rollback_pending(journal, &actor, reason)?;
            }
            let handle = envelope
                .rollback_handle
                .as_ref()
                .cloned()
                .ok_or_else(|| invalid("rollback", "rollback requires a rollback handle"))?;
            let previous = fs::read_to_string(&handle.previous_content_path)?;
            fs::write(&handle.target_path, previous.as_bytes())?;
            let restored = fs::read_to_string(&handle.target_path)?;
            let restored_hash = content_hash(&restored);
            let report = RollbackReport {
                restored: restored_hash == handle.base_hash,
                target_path: handle.target_path.clone(),
                rollback_id: handle.rollback_id.clone(),
                restored_hash,
            };
            envelope.mark_rolled_back(
                journal,
                &actor,
                format!(
                    "run={} step={} rollback_id={} restored={}",
                    run_id, step_id, report.rollback_id, report.restored
                ),
            )?;
            Ok(report)
        }

        fn explain(
            &self,
            prepared: &PreparedStepExecution,
        ) -> Result<String, SecurityExecutionError> {
            let envelope_state = prepared
                .envelope
                .as_ref()
                .map(|envelope| envelope.state.as_str())
                .unwrap_or("none");
            let lease_risk = prepared
                .outcome
                .lease
                .as_ref()
                .map(|lease| lease.risk.as_str())
                .unwrap_or("none");
            let explanation = format!(
                "security-execution status={} run={} step={} policy={} risk={} envelope={} sandbox={} firecracker={} rollback_handle={}",
                prepared.status.as_str(),
                prepared.run_id,
                prepared.step_id,
                prepared.outcome.kind.as_str(),
                lease_risk,
                envelope_state,
                prepared.sandbox_binding.is_some(),
                prepared.firecracker_binding.is_some(),
                prepared.prepared_write.is_some()
            );
            ensure_no_secret("execution_explanation", &explanation)?;
            Ok(explanation)
        }
    }

    fn prepared_without_envelope(
        status: PreparedExecutionStatus,
        request: StepExecutionRequest,
        outcome: StepPolicyOutcome,
    ) -> PreparedStepExecution {
        PreparedStepExecution {
            status,
            run_id: request.run_id,
            step_id: request.step.step_id().to_string(),
            actor: request.actor,
            outcome,
            envelope: None,
            sandbox_binding: None,
            firecracker_binding: None,
            prepared_write: None,
            execution_report: None,
        }
    }

    fn prepared_envelope<'a>(
        prepared: &'a PreparedStepExecution,
        action: &'static str,
    ) -> Result<&'a EffectEnvelope, SecurityExecutionError> {
        if prepared.status != PreparedExecutionStatus::Prepared {
            return Err(invalid(action, "security execution was not prepared"));
        }
        prepared
            .envelope
            .as_ref()
            .ok_or_else(|| invalid(action, "prepared execution is missing envelope"))
    }

    fn prepared_envelope_mut<'a>(
        prepared: &'a mut PreparedStepExecution,
        action: &'static str,
    ) -> Result<&'a mut EffectEnvelope, SecurityExecutionError> {
        if prepared.status != PreparedExecutionStatus::Prepared {
            return Err(invalid(action, "security execution was not prepared"));
        }
        prepared
            .envelope
            .as_mut()
            .ok_or_else(|| invalid(action, "prepared execution is missing envelope"))
    }

    fn validate_write_input(
        step: &PlanStep,
        normalized_params: &[(String, String)],
        input: &WriteDiffInput,
    ) -> Result<(), SecurityExecutionError> {
        let path = param_value(normalized_params, "path")
            .ok_or_else(|| invalid("prepare", "fs.write.diff requires path parameter"))?;
        let content_hash_param = param_value(normalized_params, "content_hash")
            .ok_or_else(|| invalid("prepare", "fs.write.diff requires content_hash parameter"))?;
        let expected_hash = content_hash(&input.proposed_content);
        if content_hash_param != expected_hash {
            return Err(invalid(
                "prepare",
                "write input proposed content must match content_hash parameter",
            ));
        }
        if path != input.target_path.display().to_string() {
            return Err(invalid(
                "prepare",
                "write input target path must match step path",
            ));
        }
        if let Some(base_hash) = param_value(normalized_params, "base_hash") {
            if base_hash != input.base_hash {
                return Err(invalid(
                    "prepare",
                    "write input base hash must match step base_hash",
                ));
            }
        }
        if !step.rollback().required() {
            return Err(invalid(
                "prepare",
                "fs.write.diff step must require rollback",
            ));
        }
        Ok(())
    }

    fn sandbox_operation_for(tool: &str, resource: &str) -> SandboxOperation {
        match tool {
            "http.check" => SandboxOperation::NetworkConnect {
                target: resource.to_string(),
            },
            _ => SandboxOperation::ReadDiagnostic {
                label: resource.to_string(),
            },
        }
    }

    fn param_value(params: &[(String, String)], key: &str) -> Option<String> {
        params
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.clone())
    }

    fn invalid(action: &'static str, reason: impl Into<String>) -> SecurityExecutionError {
        SecurityExecutionError::InvalidState {
            action,
            reason: reason.into(),
        }
    }

    fn ensure_no_secret(
        field: impl Into<String>,
        value: &str,
    ) -> Result<(), SecurityExecutionError> {
        if contains_secret_value(value) {
            return Err(SecurityExecutionError::SecretValue {
                field: field.into(),
            });
        }
        Ok(())
    }

    fn optional_string_json(value: Option<&str>) -> String {
        value
            .map(|value| format!("\"{}\"", escape_json(value)))
            .unwrap_or_else(|| "null".to_string())
    }

    #[cfg(test)]
    mod tests {
        use std::path::{Path, PathBuf};

        use super::*;
        use crate::agent_core::model::{
            ApprovalRequirement, RiskHint, RollbackRequirement, VerificationRule,
        };
        use crate::api::SemanticToolCall;
        use crate::audit::extract_json_string_for_tests;
        use crate::security_execution::sandbox_profile::{
            FirecrackerDependencyProbe, FirecrackerProfileRequest,
        };

        fn temp_dir(name: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!(
                "agentd-security-engine-{name}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("temp dir");
            path
        }

        fn test_journal(root: &Path) -> AuditJournal {
            AuditJournal::new(root.join("audit.jsonl"))
        }

        fn engine(root: &Path) -> DefaultSecurityExecutionEngine {
            DefaultSecurityExecutionEngine::new(root.join("shadow"))
        }

        fn step(
            step_id: &str,
            tool: &str,
            params: Vec<(&str, &str)>,
            hint: RiskClass,
            approval_required: bool,
            rollback_required: bool,
        ) -> PlanStep {
            let approval = if approval_required {
                ApprovalRequirement::operator_required("operator approval required")
                    .expect("approval")
            } else {
                ApprovalRequirement::not_required("planner says no approval").expect("approval")
            };
            let rollback = if rollback_required {
                RollbackRequirement::new(
                    true,
                    Some(format!("rollback-{step_id}")),
                    "write is rollback protected",
                )
                .expect("rollback")
            } else {
                RollbackRequirement::not_required("no rollback required").expect("rollback")
            };
            PlanStep::new(
                step_id,
                SemanticToolCall::new(tool, params),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                VerificationRule::new(format!("verify-{step_id}"), "verify output", tool)
                    .expect("verification"),
                approval,
                1,
                vec![RiskHint::new(hint, "planner risk hint").expect("risk")],
                rollback,
            )
            .expect("step")
        }

        fn approval_for(prepared: &PreparedStepExecution) -> ApprovalToken {
            let request = prepared.outcome.request.as_ref().expect("policy request");
            ApprovalToken {
                actor: request.actor.clone(),
                tool: request.tool.clone(),
                resource: request.resource.clone(),
                parameter_hash: request.parameter_hash.clone(),
                expires_at: request.now + 60,
                policy_version: request.policy_version.clone(),
            }
        }

        fn firecracker_request() -> FirecrackerProfileRequest {
            FirecrackerProfileRequest {
                firecracker_binary: "/usr/bin/firecracker".to_string(),
                jailer_binary: "/usr/bin/jailer".to_string(),
                kernel_image: "/var/lib/agentos/firecracker/vmlinux".to_string(),
                rootfs_image: "/var/lib/agentos/firecracker/rootfs.ext4".to_string(),
                network_mode: "restricted".to_string(),
                block_devices: vec!["rootfs:ro".to_string()],
                cpu_count: 2,
                memory_mib: 512,
                rate_limiter: "default-deny-egress".to_string(),
                snapshot_policy: "same-host-only".to_string(),
                dependency_probe: FirecrackerDependencyProbe::ready(),
            }
        }

        #[test]
        fn read_only_step_runs_under_sandbox_and_seals() {
            let root = temp_dir("read-only");
            let journal = test_journal(&root);
            let status = step(
                "status-nginx",
                "svc.status",
                vec![("service", "nginx")],
                RiskClass::ReadOnly,
                false,
                false,
            );

            let mut prepared = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-read", "operator", status).expect("request"),
                )
                .expect("prepare");

            assert_eq!(prepared.status, PreparedExecutionStatus::Prepared);
            assert!(prepared.sandbox_binding.is_some());
            assert_eq!(
                prepared.envelope.as_ref().expect("envelope").state,
                EffectEnvelopeState::Prepared
            );

            let report = engine(&root)
                .execute(&journal, &mut prepared)
                .expect("execute");
            assert_eq!(report.kind, ExecutionReportKind::ReadOnlySandbox);
            assert!(report.sandbox_report.is_some());
            engine(&root)
                .observe(&journal, &mut prepared, &report)
                .expect("observe");
            engine(&root)
                .verify(
                    &journal,
                    &mut prepared,
                    VerificationResult {
                        success: true,
                        reason: "diagnostic matched expected state".to_string(),
                    },
                )
                .expect("verify");
            engine(&root)
                .seal(
                    &journal,
                    &mut prepared,
                    CommitId("commit-run-read-status-nginx".to_string()),
                )
                .expect("seal");

            assert_eq!(
                prepared.envelope.as_ref().expect("envelope").state,
                EffectEnvelopeState::Sealed
            );
            let lines = journal.event_lines().expect("journal");
            assert!(lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"PolicyEvaluated\"")));
            assert!(lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"EffectPrepared\"")));
            assert!(lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"EffectObserved\"")));
            assert!(lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"CommitSealed\"")));
        }

        #[test]
        fn denied_and_paused_steps_do_not_prepare_effects() {
            let root = temp_dir("denied-paused");
            let journal = test_journal(&root);
            let shell = step(
                "shell",
                "shell.exec",
                vec![("cmd", "id")],
                RiskClass::ReadOnly,
                false,
                false,
            );
            let denied = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-denied", "operator", shell).expect("request"),
                )
                .expect("denied");
            assert_eq!(denied.status, PreparedExecutionStatus::Denied);
            assert!(denied.envelope.is_none());

            let restart = step(
                "restart-nginx",
                "svc.restart",
                vec![("service", "nginx")],
                RiskClass::ExecuteWithConfirmation,
                true,
                false,
            );
            let paused = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-paused", "operator", restart).expect("request"),
                )
                .expect("paused");
            assert_eq!(paused.status, PreparedExecutionStatus::AwaitingApproval);
            assert!(paused.envelope.is_none());

            let error = engine(&root)
                .execute(&journal, &mut paused.clone())
                .expect_err("execute without prepare rejected");
            assert_eq!(error.failure_class(), ExecutionFailureClass::FailedClosed);

            let lines = journal.event_lines().expect("journal");
            assert_eq!(
                lines
                    .iter()
                    .filter(|line| line.contains("\"event_type\":\"PolicyEvaluated\""))
                    .count(),
                2
            );
            assert!(!lines.iter().any(|line| line.contains("EffectPrepared")));
        }

        #[test]
        fn execute_with_confirmation_requires_exact_approval_before_prepare() {
            let root = temp_dir("execute-approved");
            let journal = test_journal(&root);
            let restart = step(
                "restart-nginx",
                "svc.restart",
                vec![("service", "nginx")],
                RiskClass::ExecuteWithConfirmation,
                true,
                false,
            );
            let initial = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-restart", "operator", restart.clone())
                        .expect("request"),
                )
                .expect("initial pause");
            assert_eq!(initial.status, PreparedExecutionStatus::AwaitingApproval);
            let token = approval_for(&initial);

            let mut prepared = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-restart", "operator", restart)
                        .expect("request")
                        .with_approval(token),
                )
                .expect("approved prepare");
            assert_eq!(prepared.status, PreparedExecutionStatus::Prepared);
            assert!(prepared.sandbox_binding.is_none());
            assert_eq!(
                prepared.outcome.lease.as_ref().expect("lease").risk,
                RiskClass::ExecuteWithConfirmation
            );

            let report = engine(&root)
                .execute(&journal, &mut prepared)
                .expect("execute");
            assert_eq!(report.kind, ExecutionReportKind::ControlledEffect);
            engine(&root)
                .observe(&journal, &mut prepared, &report)
                .expect("observe");
            engine(&root)
                .verify(
                    &journal,
                    &mut prepared,
                    VerificationResult {
                        success: true,
                        reason: "service reached active state".to_string(),
                    },
                )
                .expect("verify");
            engine(&root)
                .seal(
                    &journal,
                    &mut prepared,
                    CommitId("commit-run-restart".to_string()),
                )
                .expect("seal");
            assert!(engine(&root)
                .explain(&prepared)
                .expect("explain")
                .contains("envelope=Sealed"));
        }

        #[test]
        fn firecracker_profile_requires_policy_approval_before_prepare() {
            let root = temp_dir("firecracker-approved");
            let journal = test_journal(&root);
            let restart = step(
                "restart-nginx",
                "svc.restart",
                vec![("service", "nginx")],
                RiskClass::ExecuteWithConfirmation,
                true,
                false,
            );
            let initial = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-firecracker", "operator", restart.clone())
                        .expect("request")
                        .with_firecracker_profile(firecracker_request()),
                )
                .expect("initial pause");
            assert_eq!(initial.status, PreparedExecutionStatus::AwaitingApproval);
            assert!(initial.envelope.is_none());
            assert!(initial.firecracker_binding.is_none());
            let token = approval_for(&initial);

            let mut prepared = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-firecracker", "operator", restart)
                        .expect("request")
                        .with_approval(token)
                        .with_firecracker_profile(firecracker_request())
                        .with_sandbox_hints(PlannerSandboxHints {
                            requested_profile_name: Some("host-exec".to_string()),
                            requested_writable_host_paths: vec!["/".to_string()],
                            requested_network_allowlist: vec!["0.0.0.0/0".to_string()],
                            requested_persistent_write: true,
                        }),
                )
                .expect("approved prepare");

            assert_eq!(prepared.status, PreparedExecutionStatus::Prepared);
            assert!(prepared.envelope.is_some());
            assert!(prepared.sandbox_binding.is_none());
            let binding = prepared
                .firecracker_binding
                .as_ref()
                .expect("firecracker binding");
            assert_eq!(binding.class.as_str(), "firecracker-executor");
            assert_eq!(binding.ignored_planner_hints.len(), 4);
            assert!(binding
                .audit_summary
                .contains("snapshot_trust=not-portable"));
            let json = prepared.to_json().expect("prepared json");
            assert!(json.contains("\"firecracker_binding\""));
            assert!(json.contains("firecracker-executor"));
            assert!(engine(&root)
                .explain(&prepared)
                .expect("explain")
                .contains("firecracker=true"));

            let report = engine(&root)
                .execute(&journal, &mut prepared)
                .expect("execute controlled effect");
            assert_eq!(report.kind, ExecutionReportKind::ControlledEffect);
            assert!(report
                .summary
                .contains("firecracker controlled effect profile selected"));
            assert!(report.summary.contains("no_host_fallback=true"));
            assert!(!report.summary.contains("host-exec"));

            let lines = journal.event_lines().expect("journal");
            assert!(lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"EffectPrepared\"")));
            assert!(lines
                .iter()
                .any(|line| line.contains("firecracker_profile")));
            assert!(lines.iter().any(|line| {
                line.contains("policy_reason=matching approval token bound to exact parameters")
            }));
            assert!(!lines.iter().any(|line| line.contains("host-exec")));
        }

        #[test]
        fn firecracker_missing_dependency_fails_before_effect_prepare() {
            let root = temp_dir("firecracker-missing-deps");
            let journal = test_journal(&root);
            let restart = step(
                "restart-nginx",
                "svc.restart",
                vec![("service", "nginx")],
                RiskClass::ExecuteWithConfirmation,
                true,
                false,
            );
            let initial = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new(
                        "run-firecracker-missing",
                        "operator",
                        restart.clone(),
                    )
                    .expect("request"),
                )
                .expect("initial pause");
            let token = approval_for(&initial);
            let mut profile = firecracker_request();
            profile.dependency_probe.kvm_available = false;
            profile.dependency_probe.rootfs_image_available = false;

            let error = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-firecracker-missing", "operator", restart)
                        .expect("request")
                        .with_approval(token)
                        .with_firecracker_profile(profile),
                )
                .expect_err("missing firecracker dependencies fail closed");

            assert_eq!(error.failure_class(), ExecutionFailureClass::FailedClosed);
            assert!(error.reason().contains("firecracker dependencies missing"));
            assert!(error.reason().contains("no host fallback"));
            let lines = journal.event_lines().expect("journal");
            assert!(lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"PolicyEvaluated\"")));
            assert!(!lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"EffectPrepared\"")));
        }

        #[test]
        fn write_with_diff_prepares_rollback_handle_and_rolls_back_failed_verification() {
            let root = temp_dir("write-rollback");
            let target = root.join("nginx.conf");
            fs::write(&target, "port=80\n").expect("write target");
            let base_hash = content_hash("port=80\n");
            let proposed = "port=8080\n";
            let proposed_hash = content_hash(proposed);
            let target_string = target.display().to_string();
            let write_step = step(
                "write-nginx",
                "fs.write.diff",
                vec![
                    ("path", target_string.as_str()),
                    ("content_hash", proposed_hash.as_str()),
                    ("base_hash", base_hash.as_str()),
                ],
                RiskClass::WriteWithDiff,
                true,
                true,
            );
            let journal = test_journal(&root);
            let initial = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-write", "operator", write_step.clone())
                        .expect("request"),
                )
                .expect("initial pause");
            assert_eq!(initial.status, PreparedExecutionStatus::AwaitingApproval);
            let token = approval_for(&initial);
            let mut prepared = engine(&root)
                .prepare(
                    &journal,
                    StepExecutionRequest::new("run-write", "operator", write_step)
                        .expect("request")
                        .with_approval(token)
                        .with_write_input(
                            WriteDiffInput::new(&target, base_hash.clone(), proposed)
                                .expect("write input"),
                        ),
                )
                .expect("prepare write");

            assert!(prepared.prepared_write.is_some());
            assert!(prepared
                .envelope
                .as_ref()
                .expect("envelope")
                .rollback_handle
                .is_some());
            assert_eq!(
                fs::read_to_string(&target).expect("read target"),
                "port=80\n"
            );

            let report = engine(&root)
                .execute(&journal, &mut prepared)
                .expect("execute write");
            assert!(report.success);
            assert_eq!(fs::read_to_string(&target).expect("read target"), proposed);
            engine(&root)
                .observe(&journal, &mut prepared, &report)
                .expect("observe write");
            engine(&root)
                .verify(
                    &journal,
                    &mut prepared,
                    VerificationResult {
                        success: false,
                        reason: "config test failed".to_string(),
                    },
                )
                .expect("failed verification enters rollback pending");
            assert_eq!(
                prepared.envelope.as_ref().expect("envelope").state,
                EffectEnvelopeState::RollbackPending
            );

            let rollback = engine(&root)
                .rollback(&journal, &mut prepared, "verification failed")
                .expect("rollback");
            assert!(rollback.restored);
            assert_eq!(
                fs::read_to_string(&target).expect("read target"),
                "port=80\n"
            );
            assert_eq!(
                prepared.envelope.as_ref().expect("envelope").state,
                EffectEnvelopeState::RolledBack
            );
            let lines = journal.event_lines().expect("journal");
            assert!(lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"RollbackPending\"")));
            assert!(lines
                .iter()
                .any(|line| line.contains("\"event_type\":\"RollbackObserved\"")));
            assert!(!lines.iter().any(|line| {
                extract_json_string_for_tests(line, "event_type").as_deref() == Some("CommitSealed")
            }));
        }

        #[test]
        fn write_input_must_match_plan_hashes() {
            let root = temp_dir("write-mismatch");
            let target = root.join("app.conf");
            fs::write(&target, "a=1\n").expect("write target");
            let base_hash = content_hash("a=1\n");
            let target_string = target.display().to_string();
            let write_step = step(
                "write-app",
                "fs.write.diff",
                vec![
                    ("path", target_string.as_str()),
                    ("content_hash", "wrong-hash"),
                    ("base_hash", base_hash.as_str()),
                ],
                RiskClass::WriteWithDiff,
                true,
                true,
            );
            let initial_journal = test_journal(&root);
            let initial = engine(&root)
                .prepare(
                    &initial_journal,
                    StepExecutionRequest::new("run-mismatch", "operator", write_step.clone())
                        .expect("request"),
                )
                .expect("initial pause");
            let token = approval_for(&initial);
            let error = engine(&root)
                .prepare(
                    &initial_journal,
                    StepExecutionRequest::new("run-mismatch", "operator", write_step)
                        .expect("request")
                        .with_approval(token)
                        .with_write_input(
                            WriteDiffInput::new(&target, base_hash, "a=2\n").expect("write input"),
                        ),
                )
                .expect_err("hash mismatch rejected");
            assert_eq!(error.failure_class(), ExecutionFailureClass::FailedClosed);
            assert!(error.reason().contains("content_hash"));
        }
    }
}

pub mod source_to_sink {
    use std::fmt;

    use crate::agent_core::model::{contains_secret_value, TrustBoundary};
    use crate::api::{escape_json, RiskClass};
    use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
    use crate::policy::stable_parameter_hash;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SourceLabel {
        OperatorInput,
        LocalSystemOutput,
        ExternalUntrustedContent,
        ModelOutput,
        SanitizedSummary,
    }

    impl SourceLabel {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::OperatorInput => "operator-input",
                Self::LocalSystemOutput => "local-system-output",
                Self::ExternalUntrustedContent => "external-untrusted-content",
                Self::ModelOutput => "model-output",
                Self::SanitizedSummary => "sanitized-summary",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ContentSource {
        pub label: SourceLabel,
        pub trust_boundary: TrustBoundary,
        pub original_trust_boundary: TrustBoundary,
        pub content_id: String,
        pub sanitized: bool,
    }

    impl ContentSource {
        pub fn operator_input(content_id: impl Into<String>) -> Result<Self, SourceToSinkError> {
            Self::new(
                SourceLabel::OperatorInput,
                TrustBoundary::Operator,
                TrustBoundary::Operator,
                content_id,
                false,
            )
        }

        pub fn local_system_output(
            content_id: impl Into<String>,
        ) -> Result<Self, SourceToSinkError> {
            Self::new(
                SourceLabel::LocalSystemOutput,
                TrustBoundary::LocalSystem,
                TrustBoundary::LocalSystem,
                content_id,
                false,
            )
        }

        pub fn external_content(content_id: impl Into<String>) -> Result<Self, SourceToSinkError> {
            Self::new(
                SourceLabel::ExternalUntrustedContent,
                TrustBoundary::ExternalUntrusted,
                TrustBoundary::ExternalUntrusted,
                content_id,
                false,
            )
        }

        pub fn model_output(content_id: impl Into<String>) -> Result<Self, SourceToSinkError> {
            Self::new(
                SourceLabel::ModelOutput,
                TrustBoundary::ModelOutput,
                TrustBoundary::ModelOutput,
                content_id,
                false,
            )
        }

        pub fn sanitized_summary(
            source: &ContentSource,
            content_id: impl Into<String>,
        ) -> Result<Self, SourceToSinkError> {
            Self::new(
                SourceLabel::SanitizedSummary,
                TrustBoundary::SanitizedSummary,
                source.original_trust_boundary,
                content_id,
                true,
            )
        }

        pub fn to_json(&self) -> String {
            format!(
                "{{\"label\":\"{}\",\"trust_boundary\":\"{}\",\"original_trust_boundary\":\"{}\",\"content_id\":\"{}\",\"sanitized\":{}}}",
                self.label.as_str(),
                self.trust_boundary.as_str(),
                self.original_trust_boundary.as_str(),
                escape_json(&self.content_id),
                self.sanitized
            )
        }

        fn new(
            label: SourceLabel,
            trust_boundary: TrustBoundary,
            original_trust_boundary: TrustBoundary,
            content_id: impl Into<String>,
            sanitized: bool,
        ) -> Result<Self, SourceToSinkError> {
            let source = Self {
                label,
                trust_boundary,
                original_trust_boundary,
                content_id: content_id.into(),
                sanitized,
            };
            ensure_no_secret("content_source", &source.to_json())?;
            Ok(source)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SinkClass {
        ReadOnly,
        WriteWithDiff,
        ExecuteWithConfirmation,
        Privileged,
        NetworkEgress,
        SecretAccess,
    }

    impl SinkClass {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::ReadOnly => "read-only",
                Self::WriteWithDiff => "write-with-diff",
                Self::ExecuteWithConfirmation => "execute-with-confirmation",
                Self::Privileged => "privileged",
                Self::NetworkEgress => "network-egress",
                Self::SecretAccess => "secret-access",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SinkDescriptor {
        pub tool: String,
        pub class: SinkClass,
        pub risk: RiskClass,
        pub resource: String,
        pub normalized_params: Vec<(String, String)>,
    }

    impl SinkDescriptor {
        pub fn for_tool(
            tool: impl Into<String>,
            risk: RiskClass,
            resource: impl Into<String>,
            normalized_params: Vec<(String, String)>,
        ) -> Result<Self, SourceToSinkError> {
            let tool = tool.into();
            let resource = resource.into();
            let mut normalized_params = normalized_params;
            normalized_params
                .sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
            let class = classify_sink(&tool, risk, &resource, &normalized_params);
            let sink = Self {
                tool,
                class,
                risk,
                resource,
                normalized_params,
            };
            ensure_no_secret("sink_descriptor", &sink.to_json())?;
            Ok(sink)
        }

        pub fn to_json(&self) -> String {
            let params = self
                .normalized_params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{{\"key\":\"{}\",\"value\":\"{}\"}}",
                        escape_json(key),
                        escape_json(value)
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"tool\":\"{}\",\"class\":\"{}\",\"risk\":\"{}\",\"resource\":\"{}\",\"normalized_params\":[{}]}}",
                escape_json(&self.tool),
                self.class.as_str(),
                self.risk.as_str(),
                escape_json(&self.resource),
                params
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SourceToSinkRequest {
        pub run_id: String,
        pub step_id: String,
        pub actor: String,
        pub source: ContentSource,
        pub sink: SinkDescriptor,
    }

    impl SourceToSinkRequest {
        pub fn new(
            run_id: impl Into<String>,
            step_id: impl Into<String>,
            actor: impl Into<String>,
            source: ContentSource,
            sink: SinkDescriptor,
        ) -> Result<Self, SourceToSinkError> {
            let request = Self {
                run_id: run_id.into(),
                step_id: step_id.into(),
                actor: actor.into(),
                source,
                sink,
            };
            request.validate()?;
            Ok(request)
        }

        fn validate(&self) -> Result<(), SourceToSinkError> {
            ensure_no_secret("run_id", &self.run_id)?;
            ensure_no_secret("step_id", &self.step_id)?;
            ensure_no_secret("actor", &self.actor)?;
            ensure_no_secret("source", &self.source.to_json())?;
            ensure_no_secret("sink", &self.sink.to_json())?;
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SourceToSinkDecisionKind {
        Allowed,
        Denied,
    }

    impl SourceToSinkDecisionKind {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Allowed => "allowed",
                Self::Denied => "denied",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SourceToSinkDecision {
        pub kind: SourceToSinkDecisionKind,
        pub reason: String,
        pub source_label: SourceLabel,
        pub source_trust_boundary: TrustBoundary,
        pub original_trust_boundary: TrustBoundary,
        pub sink_class: SinkClass,
        pub requires_sanitized_replanning: bool,
    }

    impl SourceToSinkDecision {
        pub fn to_json(&self) -> String {
            format!(
                "{{\"decision\":\"{}\",\"reason\":\"{}\",\"source_label\":\"{}\",\"source_trust_boundary\":\"{}\",\"original_trust_boundary\":\"{}\",\"sink_class\":\"{}\",\"requires_sanitized_replanning\":{}}}",
                self.kind.as_str(),
                escape_json(&self.reason),
                self.source_label.as_str(),
                self.source_trust_boundary.as_str(),
                self.original_trust_boundary.as_str(),
                self.sink_class.as_str(),
                self.requires_sanitized_replanning
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SourceToSinkError {
        SecretValue { field: String },
        Io(String),
    }

    impl SourceToSinkError {
        pub fn reason(&self) -> String {
            match self {
                SourceToSinkError::SecretValue { field } => {
                    format!("secret-like value is not allowed in {field}")
                }
                SourceToSinkError::Io(error) => error.clone(),
            }
        }
    }

    impl fmt::Display for SourceToSinkError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.reason())
        }
    }

    impl From<std::io::Error> for SourceToSinkError {
        fn from(value: std::io::Error) -> Self {
            SourceToSinkError::Io(value.to_string())
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct SourceToSinkPolicy;

    impl SourceToSinkPolicy {
        pub fn evaluate(
            &self,
            request: &SourceToSinkRequest,
        ) -> Result<SourceToSinkDecision, SourceToSinkError> {
            request.validate()?;
            let requires_sanitized_replanning = matches!(
                request.source.original_trust_boundary,
                TrustBoundary::ExternalUntrusted | TrustBoundary::ModelOutput
            ) && !request.source.sanitized;

            let deny_reason = blocked_reason(&request.source, &request.sink);
            let (kind, reason) = if let Some(reason) = deny_reason {
                (SourceToSinkDecisionKind::Denied, reason)
            } else {
                (
                    SourceToSinkDecisionKind::Allowed,
                    format!(
                        "source {} may influence {} sink; policy adapter still owns approval and capability binding",
                        request.source.label.as_str(),
                        request.sink.class.as_str()
                    ),
                )
            };

            Ok(SourceToSinkDecision {
                kind,
                reason,
                source_label: request.source.label,
                source_trust_boundary: request.source.trust_boundary,
                original_trust_boundary: request.source.original_trust_boundary,
                sink_class: request.sink.class,
                requires_sanitized_replanning,
            })
        }

        pub fn evaluate_and_audit(
            &self,
            journal: &AuditJournal,
            request: &SourceToSinkRequest,
        ) -> Result<SourceToSinkDecision, SourceToSinkError> {
            let decision = self.evaluate(request)?;
            if decision.kind == SourceToSinkDecisionKind::Denied {
                let mut event = AuditEvent::new(
                    AuditEventType::PolicyEvaluated,
                    request.run_id.as_str(),
                    request.step_id.as_str(),
                    request.actor.as_str(),
                    format!(
                        "decision=deny source_label={} source_trust={} original_trust={} sink_class={} tool={} reason={}",
                        decision.source_label.as_str(),
                        decision.source_trust_boundary.as_str(),
                        decision.original_trust_boundary.as_str(),
                        decision.sink_class.as_str(),
                        request.sink.tool,
                        decision.reason
                    ),
                );
                event.policy_version = "source-to-sink-v1".to_string();
                event.tool_version = "source-to-sink-v1".to_string();
                event.parameter_hash = source_to_sink_hash(request);
                journal.append(&event)?;
            }
            Ok(decision)
        }
    }

    fn classify_sink(
        tool: &str,
        risk: RiskClass,
        resource: &str,
        normalized_params: &[(String, String)],
    ) -> SinkClass {
        if is_secret_sink(tool, resource, normalized_params) {
            return SinkClass::SecretAccess;
        }
        if tool == "http.check" || tool.starts_with("net.") {
            return SinkClass::NetworkEgress;
        }
        match risk {
            RiskClass::ReadOnly => SinkClass::ReadOnly,
            RiskClass::WriteWithDiff => SinkClass::WriteWithDiff,
            RiskClass::ExecuteWithConfirmation => SinkClass::ExecuteWithConfirmation,
            RiskClass::PrivilegedWithHumanApproval => SinkClass::Privileged,
            RiskClass::Never => SinkClass::Privileged,
        }
    }

    fn is_secret_sink(tool: &str, resource: &str, normalized_params: &[(String, String)]) -> bool {
        tool.starts_with("secret.")
            || resource.starts_with("secret://")
            || normalized_params.iter().any(|(key, value)| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "secret" | "password" | "token" | "apikey" | "api_key"
                ) || value.starts_with("secret://")
            })
    }

    fn blocked_reason(source: &ContentSource, sink: &SinkDescriptor) -> Option<String> {
        if source.label == SourceLabel::OperatorInput {
            return None;
        }
        if sink.class == SinkClass::ReadOnly {
            return None;
        }
        let source_name = source.label.as_str();
        let origin = source.original_trust_boundary.as_str();
        Some(format!(
            "{source_name} with original_trust={origin} cannot directly drive {} sink; require sanitized summary, replanning, and exact operator approval before capability binding",
            sink.class.as_str()
        ))
    }

    fn source_to_sink_hash(request: &SourceToSinkRequest) -> String {
        let mut params = vec![
            (
                "source_label".to_string(),
                request.source.label.as_str().to_string(),
            ),
            (
                "source_trust".to_string(),
                request.source.trust_boundary.as_str().to_string(),
            ),
            (
                "original_trust".to_string(),
                request.source.original_trust_boundary.as_str().to_string(),
            ),
            ("content_id".to_string(), request.source.content_id.clone()),
            (
                "sink_class".to_string(),
                request.sink.class.as_str().to_string(),
            ),
            ("tool".to_string(), request.sink.tool.clone()),
            ("resource".to_string(), request.sink.resource.clone()),
        ];
        params.extend(request.sink.normalized_params.clone());
        params.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        stable_parameter_hash(&params)
    }

    fn ensure_no_secret(field: impl Into<String>, value: &str) -> Result<(), SourceToSinkError> {
        if contains_secret_value(value) {
            return Err(SourceToSinkError::SecretValue {
                field: field.into(),
            });
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::agent_core::model::{
            ApprovalRequirement, PlanStep, RiskHint, RollbackRequirement, VerificationRule,
        };
        use crate::api::SemanticToolCall;
        use crate::audit::extract_json_string_for_tests;
        use crate::policy::{ApprovalToken, PolicyDecisionKind, PolicyEvaluator};
        use crate::security_execution::policy_adapter::{
            PlanStepPolicyAdapter, StepPolicyOutcome, StepPolicyOutcomeKind,
        };
        use crate::tools::ToolRouter;

        fn test_journal(name: &str) -> AuditJournal {
            let path = std::env::temp_dir().join(format!(
                "agentd-source-to-sink-{name}-{}.jsonl",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            AuditJournal::new(path)
        }

        fn sink(
            tool: &str,
            risk: RiskClass,
            resource: &str,
            params: Vec<(&str, &str)>,
        ) -> SinkDescriptor {
            SinkDescriptor::for_tool(
                tool,
                risk,
                resource,
                params
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
            )
            .expect("sink")
        }

        fn request(source: ContentSource, sink: SinkDescriptor) -> SourceToSinkRequest {
            SourceToSinkRequest::new("run-source", "step-source", "operator", source, sink)
                .expect("request")
        }

        fn restart_step() -> PlanStep {
            PlanStep::new(
                "restart-nginx",
                SemanticToolCall::new("svc.restart", vec![("service", "nginx")]),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                VerificationRule::new(
                    "nginx-active-after-restart",
                    "nginx reports active after restart",
                    "svc.status",
                )
                .expect("verification"),
                ApprovalRequirement::operator_required("service restart needs approval")
                    .expect("approval"),
                1,
                vec![RiskHint::new(
                    RiskClass::ExecuteWithConfirmation,
                    "restart changes process state",
                )
                .expect("risk")],
                RollbackRequirement::new(
                    true,
                    Some("rollback-nginx-restart"),
                    "restart requires reconciliation",
                )
                .expect("rollback"),
            )
            .expect("step")
        }

        fn exact_approval_for(outcome: &StepPolicyOutcome) -> ApprovalToken {
            let request = outcome.request.as_ref().expect("request");
            ApprovalToken {
                actor: request.actor.clone(),
                tool: request.tool.clone(),
                resource: request.resource.clone(),
                parameter_hash: request.parameter_hash.clone(),
                expires_at: request.now + 60,
                policy_version: request.policy_version.clone(),
            }
        }

        #[test]
        fn external_content_defaults_to_untrusted() {
            let source = ContentSource::external_content("webpage-1").expect("source");
            assert_eq!(source.label, SourceLabel::ExternalUntrustedContent);
            assert_eq!(source.trust_boundary, TrustBoundary::ExternalUntrusted);
            assert_eq!(
                source.original_trust_boundary,
                TrustBoundary::ExternalUntrusted
            );
            assert!(!source.sanitized);
            assert!(source.to_json().contains("external-untrusted"));
        }

        #[test]
        fn untrusted_text_cannot_directly_create_dangerous_sinks() {
            let source = ContentSource::external_content("webpage-danger").expect("source");
            let dangerous = [
                sink(
                    "svc.restart",
                    RiskClass::ExecuteWithConfirmation,
                    "nginx",
                    vec![("service", "nginx")],
                ),
                sink(
                    "fs.write.diff",
                    RiskClass::WriteWithDiff,
                    "/etc/agentd.conf",
                    vec![("path", "/etc/agentd.conf"), ("content_hash", "new")],
                ),
                sink(
                    "host.privileged",
                    RiskClass::PrivilegedWithHumanApproval,
                    "host",
                    vec![("resource", "host")],
                ),
                sink(
                    "http.check",
                    RiskClass::ReadOnly,
                    "https://evil.invalid/exfil",
                    vec![("url", "https://evil.invalid/exfil")],
                ),
                sink(
                    "secret.read",
                    RiskClass::ReadOnly,
                    "secret://prod/db",
                    vec![("secret", "secret://prod/db")],
                ),
            ];

            for sink in dangerous {
                let decision = SourceToSinkPolicy
                    .evaluate(&request(source.clone(), sink))
                    .expect("decision");
                assert_eq!(decision.kind, SourceToSinkDecisionKind::Denied);
                assert!(decision.reason.contains("cannot directly drive"));
                assert!(decision.requires_sanitized_replanning);
            }
        }

        #[test]
        fn sanitized_summary_retains_origin_and_does_not_erase_trust_boundary() {
            let source = ContentSource::external_content("webpage-2").expect("source");
            let sanitized =
                ContentSource::sanitized_summary(&source, "summary-webpage-2").expect("summary");

            assert_eq!(sanitized.label, SourceLabel::SanitizedSummary);
            assert_eq!(sanitized.trust_boundary, TrustBoundary::SanitizedSummary);
            assert_eq!(
                sanitized.original_trust_boundary,
                TrustBoundary::ExternalUntrusted
            );
            assert!(sanitized.sanitized);

            let read_only = SourceToSinkPolicy
                .evaluate(&request(
                    sanitized.clone(),
                    sink(
                        "svc.status",
                        RiskClass::ReadOnly,
                        "nginx",
                        vec![("service", "nginx")],
                    ),
                ))
                .expect("read-only");
            assert_eq!(read_only.kind, SourceToSinkDecisionKind::Allowed);

            let execute = SourceToSinkPolicy
                .evaluate(&request(
                    sanitized,
                    sink(
                        "svc.restart",
                        RiskClass::ExecuteWithConfirmation,
                        "nginx",
                        vec![("service", "nginx")],
                    ),
                ))
                .expect("execute");
            assert_eq!(execute.kind, SourceToSinkDecisionKind::Denied);
            assert_eq!(
                execute.original_trust_boundary,
                TrustBoundary::ExternalUntrusted
            );
        }

        #[test]
        fn denied_source_to_sink_attempts_are_audited_without_effect_prepared() {
            let journal = test_journal("audit-deny");
            let source = ContentSource::external_content("webpage-shell").expect("source");
            let request = SourceToSinkRequest::new(
                "run-injection",
                "restart-from-webpage",
                "operator",
                source,
                sink(
                    "svc.restart",
                    RiskClass::ExecuteWithConfirmation,
                    "nginx",
                    vec![("service", "nginx")],
                ),
            )
            .expect("request");
            let decision = SourceToSinkPolicy
                .evaluate_and_audit(&journal, &request)
                .expect("decision");

            assert_eq!(decision.kind, SourceToSinkDecisionKind::Denied);
            let lines = journal.event_lines().expect("journal");
            assert_eq!(lines.len(), 1);
            assert_eq!(
                extract_json_string_for_tests(&lines[0], "event_type").as_deref(),
                Some("PolicyEvaluated")
            );
            assert!(lines[0].contains("source_label=external-untrusted-content"));
            assert!(lines[0].contains("sink_class=execute-with-confirmation"));
            assert!(!lines[0].contains("EffectPrepared"));
        }

        #[test]
        fn operator_approved_actions_still_require_exact_approval_token_binding() {
            let source = ContentSource::operator_input("operator-intent").expect("source");
            let decision = SourceToSinkPolicy
                .evaluate(&request(
                    source,
                    sink(
                        "svc.restart",
                        RiskClass::ExecuteWithConfirmation,
                        "nginx",
                        vec![("service", "nginx")],
                    ),
                ))
                .expect("source decision");
            assert_eq!(decision.kind, SourceToSinkDecisionKind::Allowed);

            let step = restart_step();
            let journal = test_journal("approval");
            let adapter = PlanStepPolicyAdapter::new(ToolRouter, PolicyEvaluator);
            let paused = adapter
                .evaluate_step(&journal, "run-approval", "operator", &step, None)
                .expect("pause");
            assert_eq!(paused.kind, StepPolicyOutcomeKind::AwaitingApproval);
            assert_eq!(paused.decision.kind, PolicyDecisionKind::PauseForApproval);
            assert!(paused.lease.is_none());

            let token = exact_approval_for(&paused);
            let approved = adapter
                .evaluate_step(&journal, "run-approval", "operator", &step, Some(&token))
                .expect("approved");
            assert_eq!(approved.kind, StepPolicyOutcomeKind::Allowed);
            assert!(approved.lease.is_some());

            let lines = journal.event_lines().expect("journal");
            assert!(lines.iter().any(|line| line.contains("pause-for-approval")));
            assert!(lines.iter().any(|line| line.contains("decision=allow")));
            assert!(!lines.iter().any(|line| line.contains("EffectPrepared")));
        }
    }
}

pub mod secret_runtime {
    use std::fmt;

    use crate::agent_core::model::contains_secret_value;
    use crate::api::{escape_json, RiskClass};
    use crate::audit::{redact_summary, AuditEvent, AuditEventType, AuditJournal};
    use crate::policy::{stable_parameter_hash, ApprovalToken, CapabilityLease, PolicyRequest};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SecretSurface {
        PlanSpec,
        Observation,
        MemoryEntry,
        AuditSummary,
        ModelContext,
        PlannerOutput,
        CliProjection,
        TuiProjection,
    }

    impl SecretSurface {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::PlanSpec => "plan-spec",
                Self::Observation => "observation",
                Self::MemoryEntry => "memory-entry",
                Self::AuditSummary => "audit-summary",
                Self::ModelContext => "model-context",
                Self::PlannerOutput => "planner-output",
                Self::CliProjection => "cli-projection",
                Self::TuiProjection => "tui-projection",
            }
        }

        fn redacts_raw_values(self) -> bool {
            matches!(
                self,
                Self::AuditSummary | Self::CliProjection | Self::TuiProjection
            )
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BoundaryDisposition {
        Accepted,
        Redacted,
        Rejected,
    }

    impl BoundaryDisposition {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Accepted => "accepted",
                Self::Redacted => "redacted",
                Self::Rejected => "rejected",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BoundaryText {
        pub surface: SecretSurface,
        pub disposition: BoundaryDisposition,
        pub text: String,
        pub handle_refs: Vec<String>,
    }

    impl BoundaryText {
        pub fn to_json(&self) -> String {
            format!(
                "{{\"surface\":\"{}\",\"disposition\":\"{}\",\"text\":\"{}\",\"handle_refs\":{}}}",
                self.surface.as_str(),
                self.disposition.as_str(),
                escape_json(&self.text),
                string_array_json(&self.handle_refs)
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SecretHandle {
        pub uri: String,
        pub actor: String,
        pub allowed_tool: String,
        pub resource: String,
        pub purpose: String,
    }

    impl SecretHandle {
        pub fn new(
            uri: impl Into<String>,
            actor: impl Into<String>,
            allowed_tool: impl Into<String>,
            resource: impl Into<String>,
            purpose: impl Into<String>,
        ) -> Result<Self, SecretRuntimeError> {
            let handle = Self {
                uri: uri.into(),
                actor: actor.into(),
                allowed_tool: allowed_tool.into(),
                resource: resource.into(),
                purpose: purpose.into(),
            };
            handle.validate()?;
            Ok(handle)
        }

        pub fn required_parameter_hash(&self) -> String {
            stable_parameter_hash(&[
                ("actor".to_string(), self.actor.clone()),
                ("secret_handle".to_string(), self.uri.clone()),
                ("tool".to_string(), self.allowed_tool.clone()),
                ("resource".to_string(), self.resource.clone()),
            ])
        }

        pub fn to_json(&self) -> String {
            format!(
                "{{\"uri\":\"{}\",\"actor\":\"{}\",\"allowed_tool\":\"{}\",\"resource\":\"{}\",\"purpose\":\"{}\"}}",
                escape_json(&self.uri),
                escape_json(&self.actor),
                escape_json(&self.allowed_tool),
                escape_json(&self.resource),
                escape_json(&self.purpose)
            )
        }

        fn validate(&self) -> Result<(), SecretRuntimeError> {
            if !is_secret_handle(&self.uri) {
                return Err(SecretRuntimeError::InvalidHandle {
                    reason: "secret handles must be single-token secret:// references".to_string(),
                });
            }
            ensure_no_secret("secret_handle.actor", &self.actor)?;
            ensure_no_secret("secret_handle.allowed_tool", &self.allowed_tool)?;
            ensure_no_secret("secret_handle.resource", &self.resource)?;
            ensure_no_secret("secret_handle.purpose", &self.purpose)?;
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SecretUseLease {
        pub lease_id: String,
        pub actor: String,
        pub tool: String,
        pub resource: String,
        pub handle: SecretHandle,
        pub parameter_hash: String,
        pub policy_version: String,
        pub expires_at: u64,
        pub one_shot: bool,
        pub consumed: bool,
    }

    impl SecretUseLease {
        pub fn consume(&mut self, now: u64) -> Result<(), SecretRuntimeError> {
            if self.consumed {
                return Err(SecretRuntimeError::LeaseDenied {
                    reason: "secret-use lease is one-shot and already consumed".to_string(),
                });
            }
            if self.expires_at < now {
                return Err(SecretRuntimeError::LeaseDenied {
                    reason: "secret-use lease expired".to_string(),
                });
            }
            self.consumed = true;
            Ok(())
        }

        pub fn to_json(&self) -> String {
            format!(
                "{{\"lease_id\":\"{}\",\"actor\":\"{}\",\"tool\":\"{}\",\"resource\":\"{}\",\"handle\":{},\"parameter_hash\":\"{}\",\"policy_version\":\"{}\",\"expires_at\":{},\"one_shot\":{},\"consumed\":{}}}",
                escape_json(&self.lease_id),
                escape_json(&self.actor),
                escape_json(&self.tool),
                escape_json(&self.resource),
                self.handle.to_json(),
                escape_json(&self.parameter_hash),
                escape_json(&self.policy_version),
                self.expires_at,
                self.one_shot,
                self.consumed
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeMemoryEntry {
        pub key: String,
        pub value: String,
        pub handle_refs: Vec<String>,
    }

    impl RuntimeMemoryEntry {
        pub fn new(
            key: impl Into<String>,
            value: impl Into<String>,
        ) -> Result<Self, SecretRuntimeError> {
            let key = key.into();
            let value = value.into();
            ensure_no_secret("memory.key", &key)?;
            let boundary =
                SecretRuntimePolicy::inspect_boundary(SecretSurface::MemoryEntry, &value)?;
            if boundary.disposition != BoundaryDisposition::Accepted {
                return Err(SecretRuntimeError::ForbiddenRawSecret {
                    surface: SecretSurface::MemoryEntry,
                    reason: "memory entries cannot retain raw secret-like values".to_string(),
                });
            }
            Ok(Self {
                key,
                value: boundary.text,
                handle_refs: boundary.handle_refs,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SecretRuntimeError {
        InvalidHandle {
            reason: String,
        },
        ForbiddenRawSecret {
            surface: SecretSurface,
            reason: String,
        },
        LeaseDenied {
            reason: String,
        },
        SecretValue {
            field: String,
        },
        Io(String),
    }

    impl SecretRuntimeError {
        pub fn reason(&self) -> String {
            match self {
                Self::InvalidHandle { reason }
                | Self::ForbiddenRawSecret { reason, .. }
                | Self::LeaseDenied { reason } => reason.clone(),
                Self::SecretValue { field } => {
                    format!("secret-like value is not allowed in {field}")
                }
                Self::Io(error) => error.clone(),
            }
        }
    }

    impl fmt::Display for SecretRuntimeError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.reason())
        }
    }

    impl From<std::io::Error> for SecretRuntimeError {
        fn from(value: std::io::Error) -> Self {
            Self::Io(value.to_string())
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct SecretRuntimePolicy;

    impl SecretRuntimePolicy {
        pub fn inspect_boundary(
            surface: SecretSurface,
            text: &str,
        ) -> Result<BoundaryText, SecretRuntimeError> {
            let handles = extract_secret_handles(text)?;
            if contains_secret_value(text) {
                if surface.redacts_raw_values() {
                    let redacted = redact_summary(text);
                    return Ok(BoundaryText {
                        surface,
                        disposition: BoundaryDisposition::Redacted,
                        handle_refs: handles,
                        text: redacted,
                    });
                }
                return Err(SecretRuntimeError::ForbiddenRawSecret {
                    surface,
                    reason: format!("raw secret-like values cannot enter {}", surface.as_str()),
                });
            }
            Ok(BoundaryText {
                surface,
                disposition: BoundaryDisposition::Accepted,
                handle_refs: handles,
                text: text.to_string(),
            })
        }

        pub fn require_secret_use_lease(
            capability: Option<&CapabilityLease>,
            handle: &SecretHandle,
            now: u64,
        ) -> Result<SecretUseLease, SecretRuntimeError> {
            let capability = capability.ok_or_else(|| SecretRuntimeError::LeaseDenied {
                reason: "secret-use requires an explicit capability lease".to_string(),
            })?;
            handle.validate()?;
            reject_wildcards(capability)?;
            if capability.actor != handle.actor {
                return Err(SecretRuntimeError::LeaseDenied {
                    reason: "secret-use lease actor must match handle actor".to_string(),
                });
            }
            if capability.tool != handle.allowed_tool {
                return Err(SecretRuntimeError::LeaseDenied {
                    reason: "secret-use lease tool must match handle allowed_tool".to_string(),
                });
            }
            if capability.resource != handle.uri {
                return Err(SecretRuntimeError::LeaseDenied {
                    reason: "secret-use lease resource must be the exact secret handle".to_string(),
                });
            }
            if capability.risk != RiskClass::PrivilegedWithHumanApproval {
                return Err(SecretRuntimeError::LeaseDenied {
                    reason: "secret-use lease requires privileged human approval risk".to_string(),
                });
            }
            if capability.parameter_hash != handle.required_parameter_hash() {
                return Err(SecretRuntimeError::LeaseDenied {
                    reason: "secret-use lease parameter hash must bind actor, tool, resource, and handle".to_string(),
                });
            }
            if capability.expires_at < now {
                return Err(SecretRuntimeError::LeaseDenied {
                    reason: "secret-use lease expired".to_string(),
                });
            }
            Ok(SecretUseLease {
                lease_id: capability.lease_id.clone(),
                actor: capability.actor.clone(),
                tool: capability.tool.clone(),
                resource: capability.resource.clone(),
                handle: handle.clone(),
                parameter_hash: capability.parameter_hash.clone(),
                policy_version: capability.policy_version.clone(),
                expires_at: capability.expires_at,
                one_shot: true,
                consumed: false,
            })
        }

        pub fn approval_token_matches_secret_use(
            request: &PolicyRequest,
            token: &ApprovalToken,
        ) -> bool {
            token.matches(request)
                && token.actor != "*"
                && token.tool != "*"
                && token.resource != "*"
                && token.parameter_hash != "*"
                && token.policy_version != "*"
        }

        pub fn record_secret_use(
            journal: &AuditJournal,
            run_id: &str,
            step_id: &str,
            lease: &SecretUseLease,
            outcome: &str,
        ) -> Result<(), SecretRuntimeError> {
            ensure_no_secret("secret_use.outcome", outcome)?;
            let mut event = AuditEvent::new(
                AuditEventType::PolicyEvaluated,
                run_id,
                step_id,
                lease.actor.as_str(),
                format!(
                    "secret-use outcome={} handle={} lease_id={} one_shot={} consumed={}",
                    outcome, lease.handle.uri, lease.lease_id, lease.one_shot, lease.consumed
                ),
            );
            event.policy_version = lease.policy_version.clone();
            event.tool_version = "secret-runtime-v1".to_string();
            event.parameter_hash = lease.parameter_hash.clone();
            journal.append(&event)?;
            Ok(())
        }
    }

    fn reject_wildcards(capability: &CapabilityLease) -> Result<(), SecretRuntimeError> {
        if capability.actor == "*"
            || capability.tool == "*"
            || capability.resource == "*"
            || capability.parameter_hash == "*"
            || capability.policy_version == "*"
        {
            return Err(SecretRuntimeError::LeaseDenied {
                reason: "secret-use leases cannot contain wildcard approval scope".to_string(),
            });
        }
        ensure_no_secret("capability_lease", &capability.to_json())
    }

    fn extract_secret_handles(text: &str) -> Result<Vec<String>, SecretRuntimeError> {
        let mut handles = Vec::new();
        for token in text.split_whitespace() {
            let trimmed = token.trim_matches(|ch: char| {
                !ch.is_ascii_alphanumeric() && !matches!(ch, ':' | '/' | '_' | '-' | '.')
            });
            if trimmed.starts_with("secret://") {
                if !is_secret_handle(trimmed) {
                    return Err(SecretRuntimeError::InvalidHandle {
                        reason: "secret handles must be single-token secret:// references"
                            .to_string(),
                    });
                }
                handles.push(trimmed.to_string());
            }
        }
        handles.sort();
        handles.dedup();
        Ok(handles)
    }

    fn is_secret_handle(value: &str) -> bool {
        value.starts_with("secret://")
            && value.len() > "secret://".len()
            && !value.contains(char::is_whitespace)
            && !value.contains('=')
            && !value.contains('"')
            && !value.contains('\'')
            && !value.contains('`')
    }

    fn ensure_no_secret(field: impl Into<String>, value: &str) -> Result<(), SecretRuntimeError> {
        if contains_secret_value(value) {
            return Err(SecretRuntimeError::SecretValue {
                field: field.into(),
            });
        }
        Ok(())
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
        use super::*;

        fn handle() -> SecretHandle {
            SecretHandle::new(
                "secret://prod/db",
                "operator",
                "secret.read",
                "database-password",
                "database credential lookup",
            )
            .expect("handle")
        }

        fn capability_for(handle: &SecretHandle, expires_at: u64) -> CapabilityLease {
            CapabilityLease {
                lease_id: "lease-secret-read-prod-db".to_string(),
                actor: handle.actor.clone(),
                tool: handle.allowed_tool.clone(),
                resource: handle.uri.clone(),
                parameter_hash: handle.required_parameter_hash(),
                expires_at,
                policy_version: "policy-v1".to_string(),
                risk: RiskClass::PrivilegedWithHumanApproval,
            }
        }

        fn test_journal(name: &str) -> AuditJournal {
            let path = std::env::temp_dir().join(format!(
                "agentd-secret-runtime-{name}-{}.jsonl",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            AuditJournal::new(path)
        }

        #[test]
        fn secret_handles_remain_visible_on_allowed_surfaces() {
            let handle = handle();
            assert!(handle.to_json().contains("secret://prod/db"));
            let plan_text = SecretRuntimePolicy::inspect_boundary(
                SecretSurface::PlanSpec,
                "connect using secret://prod/db",
            )
            .expect("plan surface");
            assert_eq!(plan_text.disposition, BoundaryDisposition::Accepted);
            assert_eq!(plan_text.handle_refs, vec!["secret://prod/db".to_string()]);
            assert!(plan_text.to_json().contains("secret://prod/db"));
        }

        #[test]
        fn raw_secret_values_are_rejected_or_redacted_before_boundaries() {
            let model =
                SecretRuntimePolicy::inspect_boundary(SecretSurface::ModelContext, "token=abc123")
                    .expect_err("model raw secret rejected");
            assert!(model.reason().contains("model-context"));

            let memory = RuntimeMemoryEntry::new("session", "password=hunter2")
                .expect_err("memory raw secret rejected");
            assert!(memory.reason().contains("memory"));

            let audit = SecretRuntimePolicy::inspect_boundary(
                SecretSurface::AuditSummary,
                "using secret://prod/db password=hunter2 token=abc123",
            )
            .expect("audit redacted");
            assert_eq!(audit.disposition, BoundaryDisposition::Redacted);
            assert!(audit.text.contains("secret://prod/db"));
            assert!(!audit.text.contains("hunter2"));
            assert!(!audit.text.contains("token=abc123"));
        }

        #[test]
        fn secret_use_requires_explicit_narrow_capability_lease() {
            let handle = handle();
            let missing = SecretRuntimePolicy::require_secret_use_lease(None, &handle, 0)
                .expect_err("missing lease rejected");
            assert!(missing.reason().contains("explicit capability lease"));

            let capability = capability_for(&handle, 60);
            let mut lease =
                SecretRuntimePolicy::require_secret_use_lease(Some(&capability), &handle, 0)
                    .expect("secret use lease");
            assert!(lease.one_shot);
            assert!(!lease.consumed);
            lease.consume(1).expect("consume");
            assert!(lease.consumed);
            assert!(lease.consume(2).is_err());
        }

        #[test]
        fn broad_approval_and_wildcard_lease_cannot_grant_secret_use() {
            let handle = handle();
            let request = PolicyRequest {
                actor: handle.actor.clone(),
                tool: handle.allowed_tool.clone(),
                resource: handle.uri.clone(),
                risk: RiskClass::PrivilegedWithHumanApproval,
                parameter_hash: handle.required_parameter_hash(),
                policy_version: "policy-v1".to_string(),
                now: 0,
            };
            let broad_token = ApprovalToken {
                actor: request.actor.clone(),
                tool: request.tool.clone(),
                resource: "*".to_string(),
                parameter_hash: "*".to_string(),
                expires_at: 60,
                policy_version: request.policy_version.clone(),
            };
            assert!(!SecretRuntimePolicy::approval_token_matches_secret_use(
                &request,
                &broad_token
            ));

            let mut wildcard = capability_for(&handle, 60);
            wildcard.resource = "*".to_string();
            let error = SecretRuntimePolicy::require_secret_use_lease(Some(&wildcard), &handle, 0)
                .expect_err("wildcard rejected");
            assert!(error.reason().contains("wildcard"));
        }

        #[test]
        fn secret_use_audit_is_handle_only() {
            let handle = handle();
            let capability = capability_for(&handle, 60);
            let lease =
                SecretRuntimePolicy::require_secret_use_lease(Some(&capability), &handle, 0)
                    .expect("secret use lease");
            let journal = test_journal("audit");
            SecretRuntimePolicy::record_secret_use(
                &journal,
                "run-secret",
                "step-secret",
                &lease,
                "authorized",
            )
            .expect("record");
            let lines = journal.event_lines().expect("journal");
            assert_eq!(lines.len(), 1);
            assert!(lines[0].contains("secret://prod/db"));
            assert!(lines[0].contains("lease-secret-read-prod-db"));
            assert!(!lines[0].contains("hunter2"));
            assert!(!lines[0].contains("password="));
            assert!(!lines[0].contains("token="));
        }
    }
}
