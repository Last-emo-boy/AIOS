pub mod model {
    use std::fmt;

    use crate::api::{RiskClass, SemanticToolCall, escape_json};

    pub const PLAN_SCHEMA_VERSION: &str = "agent-core-plan/v1";
    pub const RUN_SCHEMA_VERSION: &str = "agent-core-run/v1";
    pub const OBSERVATION_SCHEMA_VERSION: &str = "agent-core-observation/v1";

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ModelValidationError {
        pub field: String,
        pub reason: String,
    }

    impl ModelValidationError {
        fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
            Self {
                field: field.into(),
                reason: reason.into(),
            }
        }
    }

    impl fmt::Display for ModelValidationError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{}: {}", self.field, self.reason)
        }
    }

    impl std::error::Error for ModelValidationError {}

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TrustBoundary {
        Operator,
        LocalSystem,
        ExternalUntrusted,
        ModelOutput,
        SanitizedSummary,
    }

    impl TrustBoundary {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Operator => "operator",
                Self::LocalSystem => "local-system",
                Self::ExternalUntrusted => "external-untrusted",
                Self::ModelOutput => "model-output",
                Self::SanitizedSummary => "sanitized-summary",
            }
        }

        pub fn from_str(value: &str) -> Option<Self> {
            Some(match value {
                "operator" => Self::Operator,
                "local-system" => Self::LocalSystem,
                "external-untrusted" => Self::ExternalUntrusted,
                "model-output" => Self::ModelOutput,
                "sanitized-summary" => Self::SanitizedSummary,
                _ => return None,
            })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IntentSource {
        Tui,
        Cli,
        Api,
        RecoveryReconciler,
        TestFixture,
    }

    impl IntentSource {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Tui => "tui",
                Self::Cli => "cli",
                Self::Api => "api",
                Self::RecoveryReconciler => "recovery-reconciler",
                Self::TestFixture => "test-fixture",
            }
        }

        pub fn from_str(value: &str) -> Option<Self> {
            Some(match value {
                "tui" => Self::Tui,
                "cli" => Self::Cli,
                "api" => Self::Api,
                "recovery-reconciler" => Self::RecoveryReconciler,
                "test-fixture" => Self::TestFixture,
                _ => return None,
            })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RunState {
        Accepted,
        Planning,
        Planned,
        AwaitingApproval,
        Executing,
        Observing,
        Verifying,
        Completed,
        Denied,
        Suspended,
        RollbackPending,
        Recovering,
        FailedClosed,
    }

    impl RunState {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Accepted => "Accepted",
                Self::Planning => "Planning",
                Self::Planned => "Planned",
                Self::AwaitingApproval => "AwaitingApproval",
                Self::Executing => "Executing",
                Self::Observing => "Observing",
                Self::Verifying => "Verifying",
                Self::Completed => "Completed",
                Self::Denied => "Denied",
                Self::Suspended => "Suspended",
                Self::RollbackPending => "RollbackPending",
                Self::Recovering => "Recovering",
                Self::FailedClosed => "FailedClosed",
            }
        }

        pub fn from_str(value: &str) -> Option<Self> {
            Some(match value {
                "Accepted" => Self::Accepted,
                "Planning" => Self::Planning,
                "Planned" => Self::Planned,
                "AwaitingApproval" => Self::AwaitingApproval,
                "Executing" => Self::Executing,
                "Observing" => Self::Observing,
                "Verifying" => Self::Verifying,
                "Completed" => Self::Completed,
                "Denied" => Self::Denied,
                "Suspended" => Self::Suspended,
                "RollbackPending" => Self::RollbackPending,
                "Recovering" => Self::Recovering,
                "FailedClosed" => Self::FailedClosed,
                _ => return None,
            })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ApprovalStatus {
        NotRequired,
        Pending,
        Granted,
        Denied,
        Expired,
    }

    impl ApprovalStatus {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::NotRequired => "NotRequired",
                Self::Pending => "Pending",
                Self::Granted => "Granted",
                Self::Denied => "Denied",
                Self::Expired => "Expired",
            }
        }

        pub fn from_str(value: &str) -> Option<Self> {
            Some(match value {
                "NotRequired" => Self::NotRequired,
                "Pending" => Self::Pending,
                "Granted" => Self::Granted,
                "Denied" => Self::Denied,
                "Expired" => Self::Expired,
                _ => return None,
            })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RecoveryStatus {
        None,
        ResumeFromStep,
        ReconcileEffects,
        RollbackRequired,
    }

    impl RecoveryStatus {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::None => "None",
                Self::ResumeFromStep => "ResumeFromStep",
                Self::ReconcileEffects => "ReconcileEffects",
                Self::RollbackRequired => "RollbackRequired",
            }
        }

        pub fn from_str(value: &str) -> Option<Self> {
            Some(match value {
                "None" => Self::None,
                "ResumeFromStep" => Self::ResumeFromStep,
                "ReconcileEffects" => Self::ReconcileEffects,
                "RollbackRequired" => Self::RollbackRequired,
                _ => return None,
            })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ObservationSource {
        SemanticTool,
        ModelBroker,
        Operator,
        Recovery,
    }

    impl ObservationSource {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::SemanticTool => "semantic-tool",
                Self::ModelBroker => "model-broker",
                Self::Operator => "operator",
                Self::Recovery => "recovery",
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RedactionStatus {
        NoSecretsDetected,
        Redacted,
        Rejected,
    }

    impl RedactionStatus {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::NoSecretsDetected => "no-secrets-detected",
                Self::Redacted => "redacted",
                Self::Rejected => "rejected",
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IntentCtx {
        actor: String,
        trust_boundary: TrustBoundary,
        source: IntentSource,
        working_scope: String,
        requested_outcome: String,
    }

    impl IntentCtx {
        pub fn new(
            actor: impl Into<String>,
            trust_boundary: TrustBoundary,
            source: IntentSource,
            working_scope: impl Into<String>,
            requested_outcome: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            let intent = Self {
                actor: actor.into(),
                trust_boundary,
                source,
                working_scope: working_scope.into(),
                requested_outcome: requested_outcome.into(),
            };
            intent.validate()?;
            Ok(intent)
        }

        pub fn actor(&self) -> &str {
            &self.actor
        }

        pub fn trust_boundary(&self) -> TrustBoundary {
            self.trust_boundary
        }

        pub fn source(&self) -> IntentSource {
            self.source
        }

        pub fn working_scope(&self) -> &str {
            &self.working_scope
        }

        pub fn requested_outcome(&self) -> &str {
            &self.requested_outcome
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("intent.actor", &self.actor)?;
            ensure_no_secret_value("intent.working_scope", &self.working_scope)?;
            ensure_no_secret_value("intent.requested_outcome", &self.requested_outcome)?;
            Ok(())
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"actor\":\"{}\",\"trust_boundary\":\"{}\",\"source\":\"{}\",\"working_scope\":\"{}\",\"requested_outcome\":\"{}\"}}",
                escape_json(&self.actor),
                self.trust_boundary.as_str(),
                self.source.as_str(),
                escape_json(&self.working_scope),
                escape_json(&self.requested_outcome)
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ModelEvidence {
        provider_id: String,
        model_id: String,
        model_digest: String,
        prompt_template_version: String,
        response_hash: String,
    }

    impl ModelEvidence {
        pub fn new(
            provider_id: impl Into<String>,
            model_id: impl Into<String>,
            model_digest: impl Into<String>,
            prompt_template_version: impl Into<String>,
            response_hash: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            let evidence = Self {
                provider_id: provider_id.into(),
                model_id: model_id.into(),
                model_digest: model_digest.into(),
                prompt_template_version: prompt_template_version.into(),
                response_hash: response_hash.into(),
            };
            evidence.validate()?;
            Ok(evidence)
        }

        pub fn stub() -> Self {
            Self {
                provider_id: "stub".to_string(),
                model_id: "local-only".to_string(),
                model_digest: "sha256:stub-model".to_string(),
                prompt_template_version: "stub-planner-v1".to_string(),
                response_hash: "sha256:deterministic-response".to_string(),
            }
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("model_evidence.provider_id", &self.provider_id)?;
            ensure_no_secret_value("model_evidence.model_id", &self.model_id)?;
            ensure_no_secret_value("model_evidence.model_digest", &self.model_digest)?;
            ensure_no_secret_value(
                "model_evidence.prompt_template_version",
                &self.prompt_template_version,
            )?;
            ensure_no_secret_value("model_evidence.response_hash", &self.response_hash)?;
            Ok(())
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"provider_id\":\"{}\",\"model_id\":\"{}\",\"model_digest\":\"{}\",\"prompt_template_version\":\"{}\",\"response_hash\":\"{}\"}}",
                escape_json(&self.provider_id),
                escape_json(&self.model_id),
                escape_json(&self.model_digest),
                escape_json(&self.prompt_template_version),
                escape_json(&self.response_hash)
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RiskHint {
        risk: RiskClass,
        reason: String,
    }

    impl RiskHint {
        pub fn new(
            risk: RiskClass,
            reason: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            let hint = Self {
                risk,
                reason: reason.into(),
            };
            ensure_no_secret_value("risk_hint.reason", &hint.reason)?;
            Ok(hint)
        }

        pub fn risk(&self) -> RiskClass {
            self.risk
        }

        pub fn reason(&self) -> &str {
            &self.reason
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"risk\":\"{}\",\"reason\":\"{}\"}}",
                self.risk.as_str(),
                escape_json(&self.reason)
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RollbackRequirement {
        required: bool,
        rollback_id: Option<String>,
        reason: String,
    }

    impl RollbackRequirement {
        pub fn new(
            required: bool,
            rollback_id: Option<impl Into<String>>,
            reason: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            let requirement = Self {
                required,
                rollback_id: rollback_id.map(Into::into),
                reason: reason.into(),
            };
            requirement.validate()?;
            Ok(requirement)
        }

        pub fn not_required(reason: impl Into<String>) -> Result<Self, ModelValidationError> {
            Self::new(false, None::<String>, reason)
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("rollback.reason", &self.reason)?;
            if let Some(rollback_id) = &self.rollback_id {
                ensure_no_secret_value("rollback.rollback_id", rollback_id)?;
            }
            Ok(())
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"required\":{},\"rollback_id\":{},\"reason\":\"{}\"}}",
                self.required,
                optional_string_json(self.rollback_id.as_deref()),
                escape_json(&self.reason)
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VerificationRule {
        rule_id: String,
        description: String,
        evidence_source: String,
    }

    impl VerificationRule {
        pub fn new(
            rule_id: impl Into<String>,
            description: impl Into<String>,
            evidence_source: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            let rule = Self {
                rule_id: rule_id.into(),
                description: description.into(),
                evidence_source: evidence_source.into(),
            };
            rule.validate()?;
            Ok(rule)
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("verification.rule_id", &self.rule_id)?;
            ensure_no_secret_value("verification.description", &self.description)?;
            ensure_no_secret_value("verification.evidence_source", &self.evidence_source)?;
            Ok(())
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"rule_id\":\"{}\",\"description\":\"{}\",\"evidence_source\":\"{}\"}}",
                escape_json(&self.rule_id),
                escape_json(&self.description),
                escape_json(&self.evidence_source)
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ApprovalRequirement {
        required: bool,
        reason: String,
        approver_hint: Option<String>,
    }

    impl ApprovalRequirement {
        pub fn new(
            required: bool,
            reason: impl Into<String>,
            approver_hint: Option<impl Into<String>>,
        ) -> Result<Self, ModelValidationError> {
            let requirement = Self {
                required,
                reason: reason.into(),
                approver_hint: approver_hint.map(Into::into),
            };
            requirement.validate()?;
            Ok(requirement)
        }

        pub fn not_required(reason: impl Into<String>) -> Result<Self, ModelValidationError> {
            Self::new(false, reason, None::<String>)
        }

        pub fn operator_required(reason: impl Into<String>) -> Result<Self, ModelValidationError> {
            Self::new(true, reason, Some("operator"))
        }

        pub fn required(&self) -> bool {
            self.required
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("approval.reason", &self.reason)?;
            if let Some(approver_hint) = &self.approver_hint {
                ensure_no_secret_value("approval.approver_hint", approver_hint)?;
            }
            Ok(())
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"required\":{},\"reason\":\"{}\",\"approver_hint\":{}}}",
                self.required,
                escape_json(&self.reason),
                optional_string_json(self.approver_hint.as_deref())
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PlanStep {
        step_id: String,
        call: SemanticToolCall,
        dependencies: Vec<String>,
        preconditions: Vec<String>,
        expected_observations: Vec<String>,
        verification: VerificationRule,
        approval: ApprovalRequirement,
        retry_budget: u8,
        risk_hints: Vec<RiskHint>,
        rollback: RollbackRequirement,
    }

    impl PlanStep {
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            step_id: impl Into<String>,
            call: SemanticToolCall,
            dependencies: Vec<String>,
            preconditions: Vec<String>,
            expected_observations: Vec<String>,
            verification: VerificationRule,
            approval: ApprovalRequirement,
            retry_budget: u8,
            risk_hints: Vec<RiskHint>,
            rollback: RollbackRequirement,
        ) -> Result<Self, ModelValidationError> {
            let step = Self {
                step_id: step_id.into(),
                call,
                dependencies,
                preconditions,
                expected_observations,
                verification,
                approval,
                retry_budget,
                risk_hints,
                rollback,
            };
            step.validate()?;
            Ok(step)
        }

        pub fn step_id(&self) -> &str {
            &self.step_id
        }

        pub fn call(&self) -> &SemanticToolCall {
            &self.call
        }

        pub fn risk_hints(&self) -> &[RiskHint] {
            &self.risk_hints
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("step.step_id", &self.step_id)?;
            validate_tool_call(&self.call)?;
            ensure_no_secret_values("step.dependencies", &self.dependencies)?;
            ensure_no_secret_values("step.preconditions", &self.preconditions)?;
            ensure_no_secret_values("step.expected_observations", &self.expected_observations)?;
            self.verification.validate()?;
            self.approval.validate()?;
            self.rollback.validate()?;
            for hint in &self.risk_hints {
                ensure_no_secret_value("step.risk_hints.reason", hint.reason())?;
            }
            Ok(())
        }

        fn to_json(&self) -> String {
            let risk_hints = self
                .risk_hints
                .iter()
                .map(RiskHint::to_json)
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"step_id\":\"{}\",\"call\":{},\"dependencies\":{},\"preconditions\":{},\"expected_observations\":{},\"verification\":{},\"approval\":{},\"retry_budget\":{},\"risk_hints\":[{}],\"rollback\":{}}}",
                escape_json(&self.step_id),
                semantic_tool_call_json(&self.call),
                string_array_json(&self.dependencies),
                string_array_json(&self.preconditions),
                string_array_json(&self.expected_observations),
                self.verification.to_json(),
                self.approval.to_json(),
                self.retry_budget,
                risk_hints,
                self.rollback.to_json()
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PlanSpec {
        schema_version: String,
        plan_id: String,
        planner_version: String,
        intent: IntentCtx,
        steps: Vec<PlanStep>,
        success_criteria: Vec<String>,
        model_evidence: ModelEvidence,
    }

    impl PlanSpec {
        pub fn new(
            plan_id: impl Into<String>,
            planner_version: impl Into<String>,
            intent: IntentCtx,
            steps: Vec<PlanStep>,
            success_criteria: Vec<String>,
            model_evidence: ModelEvidence,
        ) -> Result<Self, ModelValidationError> {
            let plan = Self {
                schema_version: PLAN_SCHEMA_VERSION.to_string(),
                plan_id: plan_id.into(),
                planner_version: planner_version.into(),
                intent,
                steps,
                success_criteria,
                model_evidence,
            };
            plan.validate()?;
            Ok(plan)
        }

        pub fn plan_id(&self) -> &str {
            &self.plan_id
        }

        pub fn steps(&self) -> &[PlanStep] {
            &self.steps
        }

        pub fn to_json(&self) -> String {
            let steps = self
                .steps
                .iter()
                .map(PlanStep::to_json)
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"schema_version\":\"{}\",\"plan_id\":\"{}\",\"planner_version\":\"{}\",\"intent\":{},\"steps\":[{}],\"success_criteria\":{},\"model_evidence\":{}}}",
                escape_json(&self.schema_version),
                escape_json(&self.plan_id),
                escape_json(&self.planner_version),
                self.intent.to_json(),
                steps,
                string_array_json(&self.success_criteria),
                self.model_evidence.to_json()
            )
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("plan.schema_version", &self.schema_version)?;
            ensure_no_secret_value("plan.plan_id", &self.plan_id)?;
            ensure_no_secret_value("plan.planner_version", &self.planner_version)?;
            self.intent.validate()?;
            ensure_no_secret_values("plan.success_criteria", &self.success_criteria)?;
            self.model_evidence.validate()?;
            for step in &self.steps {
                step.validate()?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ApprovalState {
        status: ApprovalStatus,
        approval_id: Option<String>,
        actor: Option<String>,
        reason: String,
    }

    impl ApprovalState {
        pub fn new(
            status: ApprovalStatus,
            approval_id: Option<impl Into<String>>,
            actor: Option<impl Into<String>>,
            reason: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            let state = Self {
                status,
                approval_id: approval_id.map(Into::into),
                actor: actor.map(Into::into),
                reason: reason.into(),
            };
            state.validate()?;
            Ok(state)
        }

        pub fn not_required() -> Self {
            Self {
                status: ApprovalStatus::NotRequired,
                approval_id: None,
                actor: None,
                reason: "no approval required".to_string(),
            }
        }

        pub fn pending(
            approval_id: impl Into<String>,
            reason: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            Self::new(
                ApprovalStatus::Pending,
                Some(approval_id),
                None::<String>,
                reason,
            )
        }

        pub fn status(&self) -> ApprovalStatus {
            self.status
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            if let Some(approval_id) = &self.approval_id {
                ensure_no_secret_value("approval_state.approval_id", approval_id)?;
            }
            if let Some(actor) = &self.actor {
                ensure_no_secret_value("approval_state.actor", actor)?;
            }
            ensure_no_secret_value("approval_state.reason", &self.reason)?;
            Ok(())
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"status\":\"{}\",\"approval_id\":{},\"actor\":{},\"reason\":\"{}\"}}",
                self.status.as_str(),
                optional_string_json(self.approval_id.as_deref()),
                optional_string_json(self.actor.as_deref()),
                escape_json(&self.reason)
            )
        }

        fn from_json(json: &str) -> Result<Self, ModelValidationError> {
            let status = ApprovalStatus::from_str(&required_json_string(json, "status")?)
                .ok_or_else(|| {
                    ModelValidationError::new("approval_state.status", "unknown status")
                })?;
            Self::new(
                status,
                nullable_json_string(json, "approval_id")?,
                nullable_json_string(json, "actor")?,
                required_json_string(json, "reason")?,
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RecoveryMarker {
        status: RecoveryStatus,
        step_id: Option<String>,
        rollback_id: Option<String>,
        reason: String,
    }

    impl RecoveryMarker {
        pub fn new(
            status: RecoveryStatus,
            step_id: Option<impl Into<String>>,
            rollback_id: Option<impl Into<String>>,
            reason: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            let marker = Self {
                status,
                step_id: step_id.map(Into::into),
                rollback_id: rollback_id.map(Into::into),
                reason: reason.into(),
            };
            marker.validate()?;
            Ok(marker)
        }

        pub fn none() -> Self {
            Self {
                status: RecoveryStatus::None,
                step_id: None,
                rollback_id: None,
                reason: "no recovery marker".to_string(),
            }
        }

        pub fn status(&self) -> RecoveryStatus {
            self.status
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            if let Some(step_id) = &self.step_id {
                ensure_no_secret_value("recovery_marker.step_id", step_id)?;
            }
            if let Some(rollback_id) = &self.rollback_id {
                ensure_no_secret_value("recovery_marker.rollback_id", rollback_id)?;
            }
            ensure_no_secret_value("recovery_marker.reason", &self.reason)?;
            Ok(())
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"status\":\"{}\",\"step_id\":{},\"rollback_id\":{},\"reason\":\"{}\"}}",
                self.status.as_str(),
                optional_string_json(self.step_id.as_deref()),
                optional_string_json(self.rollback_id.as_deref()),
                escape_json(&self.reason)
            )
        }

        fn from_json(json: &str) -> Result<Self, ModelValidationError> {
            let status = RecoveryStatus::from_str(&required_json_string(json, "status")?)
                .ok_or_else(|| {
                    ModelValidationError::new("recovery_marker.status", "unknown status")
                })?;
            Self::new(
                status,
                nullable_json_string(json, "step_id")?,
                nullable_json_string(json, "rollback_id")?,
                required_json_string(json, "reason")?,
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ObservationRef {
        observation_id: String,
        step_id: String,
        trust_label: TrustBoundary,
    }

    impl ObservationRef {
        pub fn new(
            observation_id: impl Into<String>,
            step_id: impl Into<String>,
            trust_label: TrustBoundary,
        ) -> Result<Self, ModelValidationError> {
            let reference = Self {
                observation_id: observation_id.into(),
                step_id: step_id.into(),
                trust_label,
            };
            reference.validate()?;
            Ok(reference)
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("observation_ref.observation_id", &self.observation_id)?;
            ensure_no_secret_value("observation_ref.step_id", &self.step_id)?;
            Ok(())
        }

        fn to_json(&self) -> String {
            format!(
                "{{\"observation_id\":\"{}\",\"step_id\":\"{}\",\"trust_label\":\"{}\"}}",
                escape_json(&self.observation_id),
                escape_json(&self.step_id),
                self.trust_label.as_str()
            )
        }

        fn from_json(json: &str) -> Result<Self, ModelValidationError> {
            let trust_label = TrustBoundary::from_str(&required_json_string(json, "trust_label")?)
                .ok_or_else(|| {
                    ModelValidationError::new("observation_ref.trust_label", "unknown trust label")
                })?;
            Self::new(
                required_json_string(json, "observation_id")?,
                required_json_string(json, "step_id")?,
                trust_label,
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PlanRun {
        schema_version: String,
        run_id: String,
        plan_id: String,
        frozen_plan_hash: String,
        state: RunState,
        current_step_id: Option<String>,
        approval_state: ApprovalState,
        observation_refs: Vec<ObservationRef>,
        memory_refs: Vec<String>,
        recovery_marker: RecoveryMarker,
    }

    impl PlanRun {
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            run_id: impl Into<String>,
            plan_id: impl Into<String>,
            frozen_plan_hash: impl Into<String>,
            state: RunState,
            current_step_id: Option<impl Into<String>>,
            approval_state: ApprovalState,
            observation_refs: Vec<ObservationRef>,
            memory_refs: Vec<String>,
            recovery_marker: RecoveryMarker,
        ) -> Result<Self, ModelValidationError> {
            let run = Self {
                schema_version: RUN_SCHEMA_VERSION.to_string(),
                run_id: run_id.into(),
                plan_id: plan_id.into(),
                frozen_plan_hash: frozen_plan_hash.into(),
                state,
                current_step_id: current_step_id.map(Into::into),
                approval_state,
                observation_refs,
                memory_refs,
                recovery_marker,
            };
            run.validate()?;
            Ok(run)
        }

        pub fn accepted(
            run_id: impl Into<String>,
            plan_id: impl Into<String>,
            frozen_plan_hash: impl Into<String>,
        ) -> Result<Self, ModelValidationError> {
            Self::new(
                run_id,
                plan_id,
                frozen_plan_hash,
                RunState::Accepted,
                None::<String>,
                ApprovalState::not_required(),
                Vec::new(),
                Vec::new(),
                RecoveryMarker::none(),
            )
        }

        pub fn state(&self) -> RunState {
            self.state
        }

        pub fn current_step_id(&self) -> Option<&str> {
            self.current_step_id.as_deref()
        }

        pub fn to_json(&self) -> String {
            let observation_refs = self
                .observation_refs
                .iter()
                .map(ObservationRef::to_json)
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"schema_version\":\"{}\",\"run_id\":\"{}\",\"plan_id\":\"{}\",\"frozen_plan_hash\":\"{}\",\"state\":\"{}\",\"current_step_id\":{},\"approval_state\":{},\"observation_refs\":[{}],\"memory_refs\":{},\"recovery_marker\":{}}}",
                escape_json(&self.schema_version),
                escape_json(&self.run_id),
                escape_json(&self.plan_id),
                escape_json(&self.frozen_plan_hash),
                self.state.as_str(),
                optional_string_json(self.current_step_id.as_deref()),
                self.approval_state.to_json(),
                observation_refs,
                string_array_json(&self.memory_refs),
                self.recovery_marker.to_json()
            )
        }

        pub fn from_json(json: &str) -> Result<Self, ModelValidationError> {
            let schema_version = required_json_string(json, "schema_version")?;
            if schema_version != RUN_SCHEMA_VERSION {
                return Err(ModelValidationError::new(
                    "run.schema_version",
                    "unsupported schema version",
                ));
            }
            let state = RunState::from_str(&required_json_string(json, "state")?)
                .ok_or_else(|| ModelValidationError::new("run.state", "unknown run state"))?;
            let approval_state = ApprovalState::from_json(&object_field(json, "approval_state")?)?;
            let recovery_marker =
                RecoveryMarker::from_json(&object_field(json, "recovery_marker")?)?;
            let observation_refs = object_array_field(json, "observation_refs")?
                .iter()
                .map(|item| ObservationRef::from_json(item))
                .collect::<Result<Vec<_>, _>>()?;
            Self::new(
                required_json_string(json, "run_id")?,
                required_json_string(json, "plan_id")?,
                required_json_string(json, "frozen_plan_hash")?,
                state,
                nullable_json_string(json, "current_step_id")?,
                approval_state,
                observation_refs,
                string_array_field(json, "memory_refs")?,
                recovery_marker,
            )
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("run.schema_version", &self.schema_version)?;
            ensure_no_secret_value("run.run_id", &self.run_id)?;
            ensure_no_secret_value("run.plan_id", &self.plan_id)?;
            ensure_no_secret_value("run.frozen_plan_hash", &self.frozen_plan_hash)?;
            if let Some(current_step_id) = &self.current_step_id {
                ensure_no_secret_value("run.current_step_id", current_step_id)?;
            }
            self.approval_state.validate()?;
            for reference in &self.observation_refs {
                reference.validate()?;
            }
            ensure_no_secret_values("run.memory_refs", &self.memory_refs)?;
            self.recovery_marker.validate()?;
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Observation {
        schema_version: String,
        observation_id: String,
        run_id: String,
        step_id: String,
        source: ObservationSource,
        trust_label: TrustBoundary,
        normalized_result: String,
        summary: String,
        redaction_status: RedactionStatus,
        policy_flags: Vec<String>,
    }

    impl Observation {
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            observation_id: impl Into<String>,
            run_id: impl Into<String>,
            step_id: impl Into<String>,
            source: ObservationSource,
            trust_label: TrustBoundary,
            normalized_result: impl Into<String>,
            summary: impl Into<String>,
            redaction_status: RedactionStatus,
            policy_flags: Vec<String>,
        ) -> Result<Self, ModelValidationError> {
            let observation = Self {
                schema_version: OBSERVATION_SCHEMA_VERSION.to_string(),
                observation_id: observation_id.into(),
                run_id: run_id.into(),
                step_id: step_id.into(),
                source,
                trust_label,
                normalized_result: normalized_result.into(),
                summary: summary.into(),
                redaction_status,
                policy_flags,
            };
            observation.validate()?;
            Ok(observation)
        }

        pub fn to_json(&self) -> String {
            format!(
                "{{\"schema_version\":\"{}\",\"observation_id\":\"{}\",\"run_id\":\"{}\",\"step_id\":\"{}\",\"source\":\"{}\",\"trust_label\":\"{}\",\"normalized_result\":\"{}\",\"summary\":\"{}\",\"redaction_status\":\"{}\",\"policy_flags\":{}}}",
                escape_json(&self.schema_version),
                escape_json(&self.observation_id),
                escape_json(&self.run_id),
                escape_json(&self.step_id),
                self.source.as_str(),
                self.trust_label.as_str(),
                escape_json(&self.normalized_result),
                escape_json(&self.summary),
                self.redaction_status.as_str(),
                string_array_json(&self.policy_flags)
            )
        }

        fn validate(&self) -> Result<(), ModelValidationError> {
            ensure_no_secret_value("observation.schema_version", &self.schema_version)?;
            ensure_no_secret_value("observation.observation_id", &self.observation_id)?;
            ensure_no_secret_value("observation.run_id", &self.run_id)?;
            ensure_no_secret_value("observation.step_id", &self.step_id)?;
            ensure_no_secret_value("observation.normalized_result", &self.normalized_result)?;
            ensure_no_secret_value("observation.summary", &self.summary)?;
            ensure_no_secret_values("observation.policy_flags", &self.policy_flags)?;
            Ok(())
        }
    }

    fn validate_tool_call(call: &SemanticToolCall) -> Result<(), ModelValidationError> {
        ensure_no_secret_value("tool_call.name", &call.name)?;
        for (key, value) in &call.params {
            ensure_no_secret_value("tool_call.param.name", key)?;
            if secret_key(key) && !value.starts_with("secret://") {
                return Err(ModelValidationError::new(
                    format!("tool_call.params.{key}"),
                    "secret-like parameter values must be represented as secret:// handles",
                ));
            }
            ensure_no_secret_value(format!("tool_call.params.{key}"), value)?;
        }
        Ok(())
    }

    fn ensure_no_secret_values(field: &str, values: &[String]) -> Result<(), ModelValidationError> {
        for value in values {
            ensure_no_secret_value(field, value)?;
        }
        Ok(())
    }

    fn ensure_no_secret_value(
        field: impl Into<String>,
        value: &str,
    ) -> Result<(), ModelValidationError> {
        if contains_secret_value(value) {
            return Err(ModelValidationError::new(
                field,
                "secret-like values must be redacted or stored as secret:// handles",
            ));
        }
        Ok(())
    }

    pub fn contains_secret_value(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        if lower.trim().starts_with("secret://") && !lower.trim().contains(char::is_whitespace) {
            return false;
        }
        let compact = lower.replace(['"', '\'', '`'], "");
        for key in ["password", "token", "apikey", "api_key", "secret"] {
            for separator in ["=", ":"] {
                let pattern = format!("{key}{separator}");
                let mut search = compact.as_str();
                while let Some(index) = search.find(&pattern) {
                    let tail = &search[index..];
                    if key == "secret" && tail.starts_with("secret://") {
                        search = &tail["secret://".len()..];
                        continue;
                    }
                    let after = tail[pattern.len()..].trim_start();
                    if after.starts_with("secret://") {
                        search = &after["secret://".len()..];
                        continue;
                    }
                    if after.chars().next().is_some_and(|ch| {
                        ch.is_ascii_alphanumeric()
                            || matches!(ch, '_' | '-' | '.' | '/' | '\\' | '$' | '{' | '[')
                    }) {
                        return true;
                    }
                    search = &tail[pattern.len()..];
                }
            }
        }
        false
    }

    fn secret_key(key: &str) -> bool {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "secret" | "password" | "token" | "apikey" | "api_key"
        )
    }

    fn semantic_tool_call_json(call: &SemanticToolCall) -> String {
        let mut params = call.params.clone();
        params.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let params = params
            .iter()
            .map(|(key, value)| format!("\"{}\":\"{}\"", escape_json(key), escape_json(value)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"name\":\"{}\",\"params\":{{{}}}}}",
            escape_json(&call.name),
            params
        )
    }

    fn string_array_json(values: &[String]) -> String {
        let values = values
            .iter()
            .map(|value| format!("\"{}\"", escape_json(value)))
            .collect::<Vec<_>>()
            .join(",");
        format!("[{values}]")
    }

    fn optional_string_json(value: Option<&str>) -> String {
        value
            .map(|value| format!("\"{}\"", escape_json(value)))
            .unwrap_or_else(|| "null".to_string())
    }

    fn required_json_string(json: &str, key: &str) -> Result<String, ModelValidationError> {
        nullable_json_string(json, key)?.ok_or_else(|| {
            ModelValidationError::new(format!("json.{key}"), "expected string, found null")
        })
    }

    fn nullable_json_string(json: &str, key: &str) -> Result<Option<String>, ModelValidationError> {
        let start = field_value_start(json, key)
            .ok_or_else(|| ModelValidationError::new(format!("json.{key}"), "missing field"))?;
        let rest = &json[start..];
        if rest.starts_with("null") {
            return Ok(None);
        }
        if !rest.starts_with('"') {
            return Err(ModelValidationError::new(
                format!("json.{key}"),
                "expected string or null",
            ));
        }
        let (value, _) = parse_json_string(rest).ok_or_else(|| {
            ModelValidationError::new(format!("json.{key}"), "invalid string value")
        })?;
        Ok(Some(value))
    }

    fn object_field(json: &str, key: &str) -> Result<String, ModelValidationError> {
        let start = field_value_start(json, key)
            .ok_or_else(|| ModelValidationError::new(format!("json.{key}"), "missing field"))?;
        slice_balanced(&json[start..], '{', '}')
            .ok_or_else(|| ModelValidationError::new(format!("json.{key}"), "invalid object"))
    }

    fn object_array_field(json: &str, key: &str) -> Result<Vec<String>, ModelValidationError> {
        let start = field_value_start(json, key)
            .ok_or_else(|| ModelValidationError::new(format!("json.{key}"), "missing field"))?;
        let array = slice_balanced(&json[start..], '[', ']')
            .ok_or_else(|| ModelValidationError::new(format!("json.{key}"), "invalid array"))?;
        split_object_array(&array)
    }

    fn string_array_field(json: &str, key: &str) -> Result<Vec<String>, ModelValidationError> {
        let start = field_value_start(json, key)
            .ok_or_else(|| ModelValidationError::new(format!("json.{key}"), "missing field"))?;
        let array = slice_balanced(&json[start..], '[', ']')
            .ok_or_else(|| ModelValidationError::new(format!("json.{key}"), "invalid array"))?;
        parse_string_array(&array)
    }

    fn field_value_start(json: &str, key: &str) -> Option<usize> {
        let needle = format!("\"{key}\":");
        let start = json.find(&needle)? + needle.len();
        Some(skip_json_ws(json, start))
    }

    fn skip_json_ws(json: &str, mut index: usize) -> usize {
        while let Some(ch) = json[index..].chars().next() {
            if !ch.is_whitespace() {
                break;
            }
            index += ch.len_utf8();
        }
        index
    }

    fn parse_json_string(value: &str) -> Option<(String, usize)> {
        let mut escaped = false;
        let mut output = String::new();
        let mut consumed = 1;
        let mut chars = value.chars();
        if chars.next()? != '"' {
            return None;
        }
        for ch in chars {
            consumed += ch.len_utf8();
            if escaped {
                match ch {
                    '"' => output.push('"'),
                    '\\' => output.push('\\'),
                    'n' => output.push('\n'),
                    'r' => output.push('\r'),
                    _ => output.push(ch),
                }
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => return Some((output, consumed)),
                _ => output.push(ch),
            }
        }
        None
    }

    fn slice_balanced(input: &str, open: char, close: char) -> Option<String> {
        if !input.starts_with(open) {
            return None;
        }
        let mut depth = 0usize;
        let mut in_string = false;
        let mut escaped = false;
        for (index, ch) in input.char_indices() {
            if in_string {
                if escaped {
                    escaped = false;
                    continue;
                }
                match ch {
                    '\\' => escaped = true,
                    '"' => in_string = false,
                    _ => {}
                }
                continue;
            }
            match ch {
                '"' => in_string = true,
                ch if ch == open => depth += 1,
                ch if ch == close => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(input[..=index].to_string());
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn split_object_array(array: &str) -> Result<Vec<String>, ModelValidationError> {
        let inner = array
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .ok_or_else(|| ModelValidationError::new("json.array", "invalid array"))?;
        if inner.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut objects = Vec::new();
        let mut index = 0usize;
        while index < inner.len() {
            let start = skip_json_ws(inner, index);
            let object = slice_balanced(&inner[start..], '{', '}')
                .ok_or_else(|| ModelValidationError::new("json.array", "invalid object item"))?;
            index = start + object.len();
            objects.push(object);
            let next = skip_json_ws(inner, index);
            if next >= inner.len() {
                break;
            }
            if inner[next..].starts_with(',') {
                index = next + 1;
            } else {
                return Err(ModelValidationError::new("json.array", "expected comma"));
            }
        }
        Ok(objects)
    }

    fn parse_string_array(array: &str) -> Result<Vec<String>, ModelValidationError> {
        let inner = array
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .ok_or_else(|| ModelValidationError::new("json.array", "invalid array"))?;
        if inner.trim().is_empty() {
            return Ok(Vec::new());
        }
        let mut values = Vec::new();
        let mut index = 0usize;
        while index < inner.len() {
            let start = skip_json_ws(inner, index);
            let (value, consumed) = parse_json_string(&inner[start..])
                .ok_or_else(|| ModelValidationError::new("json.array", "expected string item"))?;
            values.push(value);
            index = start + consumed;
            let next = skip_json_ws(inner, index);
            if next >= inner.len() {
                break;
            }
            if inner[next..].starts_with(',') {
                index = next + 1;
            } else {
                return Err(ModelValidationError::new("json.array", "expected comma"));
            }
        }
        Ok(values)
    }

    #[cfg(test)]
    fn risk_from_str(value: &str) -> Option<RiskClass> {
        Some(match value {
            "read-only" => RiskClass::ReadOnly,
            "write-with-diff" => RiskClass::WriteWithDiff,
            "execute-with-confirmation" => RiskClass::ExecuteWithConfirmation,
            "privileged-with-human-approval" => RiskClass::PrivilegedWithHumanApproval,
            "never" => RiskClass::Never,
            _ => return None,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn nginx_recovery_plan() -> PlanSpec {
            let intent = IntentCtx::new(
                "operator",
                TrustBoundary::Operator,
                IntentSource::Tui,
                "vm:dev",
                "recover nginx service",
            )
            .expect("intent");
            PlanSpec::new(
                "plan-nginx-recovery",
                "stub-planner-v1",
                intent,
                vec![
                    PlanStep::new(
                        "read-nginx-logs",
                        SemanticToolCall::new(
                            "svc.logs",
                            vec![("service", "nginx"), ("last", "200")],
                        ),
                        Vec::new(),
                        vec!["service exists".to_string()],
                        vec!["recent log summary".to_string()],
                        VerificationRule::new(
                            "logs-captured",
                            "logs are available for diagnosis",
                            "svc.logs",
                        )
                        .expect("verification"),
                        ApprovalRequirement::not_required("read-only diagnostic")
                            .expect("approval"),
                        1,
                        vec![
                            RiskHint::new(RiskClass::ReadOnly, "diagnostic only")
                                .expect("risk hint"),
                        ],
                        RollbackRequirement::not_required("no effect to roll back")
                            .expect("rollback"),
                    )
                    .expect("logs step"),
                    PlanStep::new(
                        "restart-nginx",
                        SemanticToolCall::new("svc.restart", vec![("service", "nginx")]),
                        vec!["read-nginx-logs".to_string()],
                        vec!["operator approves restart".to_string()],
                        vec!["service restart attempt recorded".to_string()],
                        VerificationRule::new(
                            "nginx-active-after-restart",
                            "nginx status reports active after restart",
                            "svc.status",
                        )
                        .expect("verification"),
                        ApprovalRequirement::operator_required(
                            "service restart is execute-with-confirmation",
                        )
                        .expect("approval"),
                        1,
                        vec![
                            RiskHint::new(
                                RiskClass::ExecuteWithConfirmation,
                                "restart changes service process state",
                            )
                            .expect("risk hint"),
                        ],
                        RollbackRequirement::new(
                            true,
                            Some("rollback-nginx-restart"),
                            "restart must be recoverable through service status reconciliation",
                        )
                        .expect("rollback"),
                    )
                    .expect("restart step"),
                ],
                vec![
                    "nginx reports active".to_string(),
                    "health check returns 200".to_string(),
                ],
                ModelEvidence::stub(),
            )
            .expect("plan")
        }

        #[test]
        fn service_recovery_intent_builds_plan_without_effects() {
            let plan = nginx_recovery_plan();
            let json = plan.to_json();
            assert_eq!(plan.steps().len(), 2);
            assert!(json.contains("\"name\":\"svc.restart\""));
            assert!(json.contains("\"risk_hints\""));
            assert!(!json.contains("EffectPrepared"));
            assert!(!json.contains("EffectObserved"));
            assert!(!json.contains("CommitSealed"));
        }

        #[test]
        fn plan_spec_snapshot_is_deterministic() {
            let plan = nginx_recovery_plan();
            assert_eq!(
                plan.to_json(),
                "{\"schema_version\":\"agent-core-plan/v1\",\"plan_id\":\"plan-nginx-recovery\",\"planner_version\":\"stub-planner-v1\",\"intent\":{\"actor\":\"operator\",\"trust_boundary\":\"operator\",\"source\":\"tui\",\"working_scope\":\"vm:dev\",\"requested_outcome\":\"recover nginx service\"},\"steps\":[{\"step_id\":\"read-nginx-logs\",\"call\":{\"name\":\"svc.logs\",\"params\":{\"last\":\"200\",\"service\":\"nginx\"}},\"dependencies\":[],\"preconditions\":[\"service exists\"],\"expected_observations\":[\"recent log summary\"],\"verification\":{\"rule_id\":\"logs-captured\",\"description\":\"logs are available for diagnosis\",\"evidence_source\":\"svc.logs\"},\"approval\":{\"required\":false,\"reason\":\"read-only diagnostic\",\"approver_hint\":null},\"retry_budget\":1,\"risk_hints\":[{\"risk\":\"read-only\",\"reason\":\"diagnostic only\"}],\"rollback\":{\"required\":false,\"rollback_id\":null,\"reason\":\"no effect to roll back\"}},{\"step_id\":\"restart-nginx\",\"call\":{\"name\":\"svc.restart\",\"params\":{\"service\":\"nginx\"}},\"dependencies\":[\"read-nginx-logs\"],\"preconditions\":[\"operator approves restart\"],\"expected_observations\":[\"service restart attempt recorded\"],\"verification\":{\"rule_id\":\"nginx-active-after-restart\",\"description\":\"nginx status reports active after restart\",\"evidence_source\":\"svc.status\"},\"approval\":{\"required\":true,\"reason\":\"service restart is execute-with-confirmation\",\"approver_hint\":\"operator\"},\"retry_budget\":1,\"risk_hints\":[{\"risk\":\"execute-with-confirmation\",\"reason\":\"restart changes service process state\"}],\"rollback\":{\"required\":true,\"rollback_id\":\"rollback-nginx-restart\",\"reason\":\"restart must be recoverable through service status reconciliation\"}}],\"success_criteria\":[\"nginx reports active\",\"health check returns 200\"],\"model_evidence\":{\"provider_id\":\"stub\",\"model_id\":\"local-only\",\"model_digest\":\"sha256:stub-model\",\"prompt_template_version\":\"stub-planner-v1\",\"response_hash\":\"sha256:deterministic-response\"}}"
            );
        }

        #[test]
        fn plan_run_round_trips_without_losing_state() {
            let run = PlanRun::new(
                "run-nginx-1",
                "plan-nginx-recovery",
                "sha256:frozen-plan",
                RunState::AwaitingApproval,
                Some("restart-nginx"),
                ApprovalState::pending(
                    "approval-restart-nginx",
                    "waiting for operator confirmation",
                )
                .expect("approval state"),
                vec![
                    ObservationRef::new(
                        "obs-nginx-logs",
                        "read-nginx-logs",
                        TrustBoundary::LocalSystem,
                    )
                    .expect("observation ref"),
                ],
                vec!["mem:nginx:last-diagnosis".to_string()],
                RecoveryMarker::new(
                    RecoveryStatus::ResumeFromStep,
                    Some("restart-nginx"),
                    None::<String>,
                    "approval state can be resumed after restart",
                )
                .expect("recovery marker"),
            )
            .expect("run");
            let json = run.to_json();
            let loaded = PlanRun::from_json(&json).expect("load run");
            assert_eq!(loaded, run);
            assert_eq!(loaded.state(), RunState::AwaitingApproval);
            assert_eq!(loaded.current_step_id(), Some("restart-nginx"));
        }

        #[test]
        fn risk_hints_are_not_authority() {
            let plan = nginx_recovery_plan();
            let restart = plan
                .steps()
                .iter()
                .find(|step| step.step_id() == "restart-nginx")
                .expect("restart step");
            assert_eq!(
                restart.risk_hints()[0].risk(),
                RiskClass::ExecuteWithConfirmation
            );
            let json = plan.to_json();
            assert!(json.contains("\"risk_hints\""));
            assert!(json.contains("\"approval\":{\"required\":true"));
            assert!(!json.contains("policy_decision"));
            assert!(!json.contains("\"decision\""));
        }

        #[test]
        fn secret_values_are_rejected_but_handles_allowed() {
            assert!(
                IntentCtx::new(
                    "operator",
                    TrustBoundary::Operator,
                    IntentSource::Tui,
                    "vm:dev",
                    "restart service with password=hunter2",
                )
                .is_err()
            );

            let bad_observation = Observation::new(
                "obs-1",
                "run-1",
                "step-1",
                ObservationSource::SemanticTool,
                TrustBoundary::LocalSystem,
                "token=abc123",
                "tool returned token=abc123",
                RedactionStatus::NoSecretsDetected,
                Vec::new(),
            );
            assert!(bad_observation.is_err());

            let handle_call = SemanticToolCall::new(
                "fs.read",
                vec![("path", "/run/secrets/ref"), ("token", "secret://db-prod")],
            );
            assert!(validate_tool_call(&handle_call).is_ok());
            assert!(!contains_secret_value("secret://db-prod"));
        }

        #[test]
        fn model_construction_does_not_emit_side_effect_audit_events() {
            let path = std::env::temp_dir().join(format!(
                "agent-core-model-no-audit-{}.jsonl",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            let plan = nginx_recovery_plan();
            let run = PlanRun::accepted(
                "run-nginx-2",
                plan.plan_id().to_string(),
                "sha256:frozen-plan",
            )
            .expect("run");

            assert!(!path.exists());
            let combined = format!("{}{}", plan.to_json(), run.to_json());
            assert!(!combined.contains("EffectPrepared"));
            assert!(!combined.contains("EffectObserved"));
            assert!(!combined.contains("CommitSealed"));
        }

        #[test]
        fn risk_string_mapping_covers_runtime_classes() {
            assert_eq!(risk_from_str("read-only"), Some(RiskClass::ReadOnly));
            assert_eq!(
                risk_from_str("execute-with-confirmation"),
                Some(RiskClass::ExecuteWithConfirmation)
            );
            assert_eq!(risk_from_str("unknown"), None);
        }
    }
}
