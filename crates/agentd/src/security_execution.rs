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
                    "prepared tool={} risk={} parameter_hash={}",
                    self.tool,
                    self.risk().as_str(),
                    self.parameter_hash()
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
                "{{\"run_id\":\"{}\",\"step_id\":\"{}\",\"tool\":\"{}\",\"state\":\"{}\",\"normalized_params\":[{}],\"parameter_hash\":\"{}\",\"policy_decision\":{},\"lease\":{},\"sandbox_profile\":{},\"prepared_event\":{},\"observed_event\":{},\"verification_result\":{},\"rollback_handle\":{},\"commit_id\":{}}}",
                escape_json(&self.run_id),
                escape_json(&self.step_id),
                escape_json(&self.tool),
                self.state.as_str(),
                params,
                escape_json(&self.parameter_hash()),
                self.policy_decision.to_json(),
                lease,
                sandbox_profile,
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
                    format!("expected {}, got {}", expected.as_str(), self.state.as_str()),
                ));
            }
            Ok(())
        }

        fn invalid(
            &self,
            action: &'static str,
            reason: impl Into<String>,
        ) -> EffectEnvelopeError {
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

    fn ensure_no_secret(
        field: impl Into<String>,
        value: &str,
    ) -> Result<(), EffectEnvelopeError> {
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
                .seal(&journal, "operator", CommitId("commit-without-verify".to_string()))
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

    use crate::agent_core::model::{contains_secret_value, PlanStep};
    use crate::api::{escape_json, RiskClass};
    use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
    use crate::policy::{
        stable_parameter_hash, ApprovalToken, CapabilityLease, PolicyDecision,
        PolicyDecisionKind, PolicyEvaluator, PolicyRequest,
    };
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
            step: &PlanStep,
            approval: Option<&ApprovalToken>,
        ) -> Result<StepPolicyOutcome, StepPolicyError> {
            self.evaluate_step_at(journal, run_id, actor, step, approval, 0)
        }

        pub fn evaluate_step_at(
            &self,
            journal: &AuditJournal,
            run_id: &str,
            actor: &str,
            step: &PlanStep,
            approval: Option<&ApprovalToken>,
            now: u64,
        ) -> Result<StepPolicyOutcome, StepPolicyError> {
            ensure_no_secret("run_id", run_id)?;
            ensure_no_secret("actor", actor)?;
            ensure_no_secret("step_id", step.step_id())?;
            let planner_risk_hints = step
                .risk_hints()
                .iter()
                .map(|hint| hint.risk())
                .collect::<Vec<_>>();

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
            step: &PlanStep,
            rejection: ToolRejection,
            planner_risk_hints: Vec<RiskClass>,
        ) -> Result<StepPolicyOutcome, StepPolicyError> {
            ensure_no_secret("route_rejection", &rejection.reason)?;
            let parameter_hash = stable_call_hash(step);
            let decision = PolicyDecision {
                kind: PolicyDecisionKind::Deny,
                risk: RiskClass::Never,
                reason: format!("tool routing denied before policy lease: {}", rejection.reason),
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

    fn stable_call_hash(step: &PlanStep) -> String {
        let mut params = step.call().params.clone();
        params.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        stable_parameter_hash(&params)
    }

    fn ensure_no_secret(
        field: impl Into<String>,
        value: &str,
    ) -> Result<(), StepPolicyError> {
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
            ApprovalRequirement, RiskHint, RollbackRequirement, VerificationRule,
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
                VerificationRule::new(
                    format!("verify-{step_id}"),
                    "verification rule",
                    tool,
                )
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
                .evaluate_step(
                    &initial_journal,
                    "run-exact",
                    "operator",
                    &restart,
                    None,
                )
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
                    format!("sandbox profile class {} is unsupported: {reason}", class.as_str())
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

    fn ensure_no_secret(
        field: impl Into<String>,
        value: &str,
    ) -> Result<(), SandboxProfileError> {
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
            assert!(binding.audit_summary.contains("persistent_write_allowed:false"));
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
                assert!(error.reason().contains(SandboxProfileClass::for_risk(risk).as_str()));
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

    }
}
