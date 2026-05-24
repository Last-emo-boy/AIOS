use crate::model::{contains_secret_value, RiskClass, TrustBoundary};

pub const CAPABILITY_CONTRACT_SCHEMA_VERSION: &str = "agentos.capability-contract.v1";
pub const PACKAGE_ADAPTER_REPORT_SCHEMA_VERSION: &str = "agentos.package-adapter-report.v1";
pub const CONTENT_ADAPTER_REPORT_SCHEMA_VERSION: &str = "agentos.content-adapter-report.v1";
pub const FIRECRACKER_ADAPTER_REPORT_SCHEMA_VERSION: &str =
    "agentos.firecracker-adapter-report.v1";
pub const SUPPORT_BUNDLE_MANIFEST_SCHEMA_VERSION: &str = "agentos.support-bundle-manifest.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityOwner {
    RuntimeContracts,
    AgentCore,
    SecurityExecution,
    Agentd,
    Scripts,
    Packaging,
}

impl CapabilityOwner {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeContracts => "runtime_contracts",
            Self::AgentCore => "agent_core",
            Self::SecurityExecution => "security_execution",
            Self::Agentd => "agentd",
            Self::Scripts => "scripts",
            Self::Packaging => "packaging",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionalDependencyBehavior {
    LocalOnlyBaseline,
    FailClosedBeforeEffectPrepared,
    OptionalIntegration,
}

impl OptionalDependencyBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnlyBaseline => "local-only-baseline",
            Self::FailClosedBeforeEffectPrepared => "fail-closed-before-effect-prepared",
            Self::OptionalIntegration => "optional-integration",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityContract {
    pub capability_id: String,
    pub primary_owner: CapabilityOwner,
    pub integration_layers: Vec<CapabilityOwner>,
    pub semantic_tools: Vec<String>,
    pub risk_class: RiskClass,
    pub optional_dependency_behavior: OptionalDependencyBehavior,
    pub local_only_replay: String,
    pub side_effect_authority: CapabilityOwner,
}

impl CapabilityContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_id: impl Into<String>,
        primary_owner: CapabilityOwner,
        integration_layers: Vec<CapabilityOwner>,
        semantic_tools: Vec<impl Into<String>>,
        risk_class: RiskClass,
        optional_dependency_behavior: OptionalDependencyBehavior,
        local_only_replay: impl Into<String>,
        side_effect_authority: CapabilityOwner,
    ) -> Result<Self, CapabilityContractError> {
        let contract = Self {
            capability_id: capability_id.into(),
            primary_owner,
            integration_layers,
            semantic_tools: semantic_tools.into_iter().map(Into::into).collect(),
            risk_class,
            optional_dependency_behavior,
            local_only_replay: local_only_replay.into(),
            side_effect_authority,
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), CapabilityContractError> {
        ensure_text("capability_id", &self.capability_id)?;
        ensure_text("local_only_replay", &self.local_only_replay)?;
        if self.integration_layers.is_empty() {
            return Err(CapabilityContractError::Invalid {
                field: "integration_layers",
                reason: "capability must declare integration layers".to_string(),
            });
        }
        if !self.integration_layers.contains(&self.primary_owner) {
            return Err(CapabilityContractError::Invalid {
                field: "primary_owner",
                reason: "primary owner must appear in integration layers".to_string(),
            });
        }
        if matches!(
            self.risk_class,
            RiskClass::WriteWithDiff
                | RiskClass::ExecuteWithConfirmation
                | RiskClass::PrivilegedWithHumanApproval
        ) && self.side_effect_authority != CapabilityOwner::SecurityExecution
        {
            return Err(CapabilityContractError::Invalid {
                field: "side_effect_authority",
                reason: "side-effecting capabilities must use SecurityExecution as authority"
                    .to_string(),
            });
        }
        for tool in &self.semantic_tools {
            ensure_text("semantic_tools", tool)?;
            if tool == "shell.exec" {
                return Err(CapabilityContractError::Invalid {
                    field: "semantic_tools",
                    reason: "normal-mode shell.exec is not a functional capability".to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let layers = self
            .integration_layers
            .iter()
            .map(|owner| owner.as_str().to_string())
            .collect::<Vec<_>>();
        format!(
            "{{\"schema\":\"{}\",\"capability_id\":\"{}\",\"primary_owner\":\"{}\",\"integration_layers\":{},\"semantic_tools\":{},\"risk_class\":\"{}\",\"optional_dependency_behavior\":\"{}\",\"local_only_replay\":\"{}\",\"side_effect_authority\":\"{}\"}}",
            CAPABILITY_CONTRACT_SCHEMA_VERSION,
            escape_json(&self.capability_id),
            self.primary_owner.as_str(),
            string_array_json(&layers),
            string_array_json(&self.semantic_tools),
            self.risk_class.as_str(),
            self.optional_dependency_behavior.as_str(),
            escape_json(&self.local_only_replay),
            self.side_effect_authority.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIdentity {
    pub name: String,
    pub version: String,
    pub source_uri: String,
    pub source_digest: String,
    pub repository_identity: String,
}

impl PackageIdentity {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        source_uri: impl Into<String>,
        source_digest: impl Into<String>,
        repository_identity: impl Into<String>,
    ) -> Result<Self, CapabilityContractError> {
        let identity = Self {
            name: name.into(),
            version: version.into(),
            source_uri: source_uri.into(),
            source_digest: source_digest.into(),
            repository_identity: repository_identity.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), CapabilityContractError> {
        ensure_text("package.name", &self.name)?;
        ensure_text("package.version", &self.version)?;
        ensure_text("package.source_uri", &self.source_uri)?;
        ensure_text("package.source_digest", &self.source_digest)?;
        ensure_text("package.repository_identity", &self.repository_identity)?;
        if !self.source_digest.starts_with("sha256:") {
            return Err(CapabilityContractError::Invalid {
                field: "package.source_digest",
                reason: "package source digest must be sha256-bound".to_string(),
            });
        }
        Ok(())
    }

    pub fn resource(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"name\":\"{}\",\"version\":\"{}\",\"source_uri\":\"{}\",\"source_digest\":\"{}\",\"repository_identity\":\"{}\"}}",
            escape_json(&self.name),
            escape_json(&self.version),
            escape_json(&self.source_uri),
            escape_json(&self.source_digest),
            escape_json(&self.repository_identity)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageAdapterPhase {
    MetadataResolved,
    IsolatedInstall,
    IsolatedSmoke,
    HostCheckpoint,
    HostPromotion,
    HostVerification,
    RollbackPrepared,
    Denied,
    FailedClosed,
}

impl PackageAdapterPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetadataResolved => "metadata-resolved",
            Self::IsolatedInstall => "isolated-install",
            Self::IsolatedSmoke => "isolated-smoke",
            Self::HostCheckpoint => "host-checkpoint",
            Self::HostPromotion => "host-promotion",
            Self::HostVerification => "host-verification",
            Self::RollbackPrepared => "rollback-prepared",
            Self::Denied => "denied",
            Self::FailedClosed => "failed-closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageAdapterReport {
    pub identity: PackageIdentity,
    pub phase: PackageAdapterPhase,
    pub isolated_validation_passed: bool,
    pub host_promotion_approved: bool,
    pub host_mutation_attempted: bool,
    pub rollback_id: Option<String>,
    pub retained_artifacts: Vec<String>,
    pub failure: Option<String>,
}

impl PackageAdapterReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: PackageIdentity,
        phase: PackageAdapterPhase,
        isolated_validation_passed: bool,
        host_promotion_approved: bool,
        host_mutation_attempted: bool,
        rollback_id: Option<String>,
        retained_artifacts: Vec<impl Into<String>>,
        failure: Option<impl Into<String>>,
    ) -> Result<Self, CapabilityContractError> {
        let report = Self {
            identity,
            phase,
            isolated_validation_passed,
            host_promotion_approved,
            host_mutation_attempted,
            rollback_id,
            retained_artifacts: retained_artifacts.into_iter().map(Into::into).collect(),
            failure: failure.map(Into::into),
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), CapabilityContractError> {
        self.identity.validate()?;
        if self.host_promotion_approved && !self.isolated_validation_passed {
            return Err(CapabilityContractError::Invalid {
                field: "host_promotion_approved",
                reason: "host promotion requires isolated validation".to_string(),
            });
        }
        if self.host_promotion_approved && self.rollback_id.as_deref().unwrap_or("").is_empty() {
            return Err(CapabilityContractError::Invalid {
                field: "rollback_id",
                reason: "host promotion requires rollback binding".to_string(),
            });
        }
        if self.host_mutation_attempted && !self.host_promotion_approved {
            return Err(CapabilityContractError::Invalid {
                field: "host_mutation_attempted",
                reason: "host mutation cannot be attempted before approved promotion".to_string(),
            });
        }
        if let Some(rollback_id) = &self.rollback_id {
            ensure_text("rollback_id", rollback_id)?;
        }
        for artifact in &self.retained_artifacts {
            ensure_text("retained_artifact", artifact)?;
            if !(artifact.ends_with(".json") || artifact.ends_with(".redacted")) {
                return Err(CapabilityContractError::Invalid {
                    field: "retained_artifacts",
                    reason: "package adapter artifacts must be structured or redacted".to_string(),
                });
            }
        }
        if let Some(failure) = &self.failure {
            ensure_text("failure", failure)?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"identity\":{},\"phase\":\"{}\",\"isolated_validation_passed\":{},\"host_promotion_approved\":{},\"host_mutation_attempted\":{},\"rollback_id\":{},\"retained_artifacts\":{},\"failure\":{}}}",
            PACKAGE_ADAPTER_REPORT_SCHEMA_VERSION,
            self.identity.to_json(),
            self.phase.as_str(),
            self.isolated_validation_passed,
            self.host_promotion_approved,
            self.host_mutation_attempted,
            optional_string_json(self.rollback_id.as_deref()),
            string_array_json(&self.retained_artifacts),
            optional_string_json(self.failure.as_deref())
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentFetchContract {
    pub content_id: String,
    pub source_uri: String,
    pub content_digest: String,
    pub max_bytes: usize,
    pub trust_boundary: TrustBoundary,
}

impl ContentFetchContract {
    pub fn new(
        content_id: impl Into<String>,
        source_uri: impl Into<String>,
        content_digest: impl Into<String>,
        max_bytes: usize,
    ) -> Result<Self, CapabilityContractError> {
        let contract = Self {
            content_id: content_id.into(),
            source_uri: source_uri.into(),
            content_digest: content_digest.into(),
            max_bytes,
            trust_boundary: TrustBoundary::ExternalUntrusted,
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), CapabilityContractError> {
        ensure_text("content_id", &self.content_id)?;
        ensure_text("source_uri", &self.source_uri)?;
        ensure_text("content_digest", &self.content_digest)?;
        if self.max_bytes == 0 {
            return Err(CapabilityContractError::Invalid {
                field: "max_bytes",
                reason: "content fetch max bytes must be greater than zero".to_string(),
            });
        }
        if !self.content_digest.starts_with("sha256:") {
            return Err(CapabilityContractError::Invalid {
                field: "content_digest",
                reason: "content digest must be sha256-bound".to_string(),
            });
        }
        if self.trust_boundary != TrustBoundary::ExternalUntrusted {
            return Err(CapabilityContractError::Invalid {
                field: "trust_boundary",
                reason: "external content defaults to untrusted".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"content_id\":\"{}\",\"source_uri\":\"{}\",\"content_digest\":\"{}\",\"max_bytes\":{},\"trust_boundary\":\"{}\"}}",
            escape_json(&self.content_id),
            escape_json(&self.source_uri),
            escape_json(&self.content_digest),
            self.max_bytes,
            self.trust_boundary.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentAdapterReport {
    pub fetch: ContentFetchContract,
    pub bytes_read: usize,
    pub sanitized_summary: String,
    pub direct_tool_call_allowed: bool,
    pub denied_sink_visible: bool,
    pub effect_prepared: bool,
}

impl ContentAdapterReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fetch: ContentFetchContract,
        bytes_read: usize,
        sanitized_summary: impl Into<String>,
        direct_tool_call_allowed: bool,
        denied_sink_visible: bool,
        effect_prepared: bool,
    ) -> Result<Self, CapabilityContractError> {
        let report = Self {
            fetch,
            bytes_read,
            sanitized_summary: sanitized_summary.into(),
            direct_tool_call_allowed,
            denied_sink_visible,
            effect_prepared,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), CapabilityContractError> {
        self.fetch.validate()?;
        ensure_text("sanitized_summary", &self.sanitized_summary)?;
        if self.bytes_read > self.fetch.max_bytes {
            return Err(CapabilityContractError::Invalid {
                field: "bytes_read",
                reason: "fetched content exceeds max bytes".to_string(),
            });
        }
        if self.direct_tool_call_allowed {
            return Err(CapabilityContractError::Invalid {
                field: "direct_tool_call_allowed",
                reason: "sanitized summaries cannot authorize direct tool calls".to_string(),
            });
        }
        if self.denied_sink_visible && self.effect_prepared {
            return Err(CapabilityContractError::Invalid {
                field: "effect_prepared",
                reason: "denied source-to-sink attempts must not prepare effects".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"fetch\":{},\"bytes_read\":{},\"sanitized_summary\":\"{}\",\"direct_tool_call_allowed\":{},\"denied_sink_visible\":{},\"effect_prepared\":{}}}",
            CONTENT_ADAPTER_REPORT_SCHEMA_VERSION,
            self.fetch.to_json(),
            self.bytes_read,
            escape_json(&self.sanitized_summary),
            self.direct_tool_call_allowed,
            self.denied_sink_visible,
            self.effect_prepared
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirecrackerAdapterReport {
    pub profile_id: String,
    pub dependency_probe: Vec<String>,
    pub missing_dependencies: Vec<String>,
    pub effect_prepared: bool,
    pub fallback_used: bool,
    pub artifact_redaction: String,
}

impl FirecrackerAdapterReport {
    pub fn new(
        profile_id: impl Into<String>,
        dependency_probe: Vec<impl Into<String>>,
        missing_dependencies: Vec<impl Into<String>>,
        effect_prepared: bool,
        fallback_used: bool,
        artifact_redaction: impl Into<String>,
    ) -> Result<Self, CapabilityContractError> {
        let report = Self {
            profile_id: profile_id.into(),
            dependency_probe: dependency_probe.into_iter().map(Into::into).collect(),
            missing_dependencies: missing_dependencies.into_iter().map(Into::into).collect(),
            effect_prepared,
            fallback_used,
            artifact_redaction: artifact_redaction.into(),
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), CapabilityContractError> {
        ensure_text("profile_id", &self.profile_id)?;
        ensure_text("artifact_redaction", &self.artifact_redaction)?;
        for dependency in self
            .dependency_probe
            .iter()
            .chain(self.missing_dependencies.iter())
        {
            ensure_text("dependency", dependency)?;
        }
        if !self.missing_dependencies.is_empty() && self.effect_prepared {
            return Err(CapabilityContractError::Invalid {
                field: "effect_prepared",
                reason: "missing Firecracker dependencies must fail before EffectPrepared"
                    .to_string(),
            });
        }
        if !self.missing_dependencies.is_empty() && self.fallback_used {
            return Err(CapabilityContractError::Invalid {
                field: "fallback_used",
                reason: "Firecracker missing dependencies cannot fall back to host execution"
                    .to_string(),
            });
        }
        if self.artifact_redaction != "secret-values-redacted" {
            return Err(CapabilityContractError::Invalid {
                field: "artifact_redaction",
                reason: "Firecracker artifacts must declare secret-value redaction".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"profile_id\":\"{}\",\"dependency_probe\":{},\"missing_dependencies\":{},\"effect_prepared\":{},\"fallback_used\":{},\"artifact_redaction\":\"{}\"}}",
            FIRECRACKER_ADAPTER_REPORT_SCHEMA_VERSION,
            escape_json(&self.profile_id),
            string_array_json(&self.dependency_probe),
            string_array_json(&self.missing_dependencies),
            self.effect_prepared,
            self.fallback_used,
            escape_json(&self.artifact_redaction)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleManifest {
    pub bundle_id: String,
    pub run_ids: Vec<String>,
    pub audit_event_range: String,
    pub audit_hash_chain: String,
    pub redaction_status: String,
    pub includes_raw_secret: bool,
}

impl SupportBundleManifest {
    pub fn new(
        bundle_id: impl Into<String>,
        run_ids: Vec<impl Into<String>>,
        audit_event_range: impl Into<String>,
        audit_hash_chain: impl Into<String>,
        redaction_status: impl Into<String>,
        includes_raw_secret: bool,
    ) -> Result<Self, CapabilityContractError> {
        let manifest = Self {
            bundle_id: bundle_id.into(),
            run_ids: run_ids.into_iter().map(Into::into).collect(),
            audit_event_range: audit_event_range.into(),
            audit_hash_chain: audit_hash_chain.into(),
            redaction_status: redaction_status.into(),
            includes_raw_secret,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), CapabilityContractError> {
        ensure_text("bundle_id", &self.bundle_id)?;
        ensure_text("audit_event_range", &self.audit_event_range)?;
        ensure_text("audit_hash_chain", &self.audit_hash_chain)?;
        ensure_text("redaction_status", &self.redaction_status)?;
        if self.run_ids.is_empty() {
            return Err(CapabilityContractError::Invalid {
                field: "run_ids",
                reason: "support bundles must identify source run ids".to_string(),
            });
        }
        for run_id in &self.run_ids {
            ensure_text("run_id", run_id)?;
        }
        if self.includes_raw_secret || self.redaction_status != "secret-values-redacted" {
            return Err(CapabilityContractError::Invalid {
                field: "redaction_status",
                reason: "support bundles cannot include raw secrets".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"bundle_id\":\"{}\",\"run_ids\":{},\"audit_event_range\":\"{}\",\"audit_hash_chain\":\"{}\",\"redaction_status\":\"{}\",\"includes_raw_secret\":{}}}",
            SUPPORT_BUNDLE_MANIFEST_SCHEMA_VERSION,
            escape_json(&self.bundle_id),
            string_array_json(&self.run_ids),
            escape_json(&self.audit_event_range),
            escape_json(&self.audit_hash_chain),
            escape_json(&self.redaction_status),
            self.includes_raw_secret
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityContractError {
    Invalid {
        field: &'static str,
        reason: String,
    },
    SecretValue {
        field: &'static str,
    },
}

impl CapabilityContractError {
    pub fn reason(&self) -> String {
        match self {
            Self::Invalid { reason, .. } => reason.clone(),
            Self::SecretValue { field } => {
                format!("secret-like value is not allowed in {field}")
            }
        }
    }
}

impl std::fmt::Display for CapabilityContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason())
    }
}

impl std::error::Error for CapabilityContractError {}

fn ensure_text(field: &'static str, value: &str) -> Result<(), CapabilityContractError> {
    if value.trim().is_empty() {
        return Err(CapabilityContractError::Invalid {
            field,
            reason: "value must not be empty".to_string(),
        });
    }
    if contains_secret_value(value) {
        return Err(CapabilityContractError::SecretValue { field });
    }
    Ok(())
}

fn optional_string_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn string_array_json(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{}\"", escape_json(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package_identity() -> PackageIdentity {
        PackageIdentity::new(
            "nginx-agent-plugin",
            "1.2.3",
            "https://packages.example/nginx-agent-plugin_1.2.3.deb",
            "sha256:0123456789abcdef",
            "debian:bookworm:agentos-main",
        )
        .expect("identity")
    }

    #[test]
    fn side_effecting_capability_requires_security_execution_authority() {
        let error = CapabilityContract::new(
            "package-manager",
            CapabilityOwner::AgentCore,
            vec![CapabilityOwner::AgentCore, CapabilityOwner::Agentd],
            vec!["pkg.host.install"],
            RiskClass::PrivilegedWithHumanApproval,
            OptionalDependencyBehavior::FailClosedBeforeEffectPrepared,
            "scripts/functional-capability-replay.ps1 --package",
            CapabilityOwner::Agentd,
        )
        .expect_err("agentd cannot be side-effect authority");

        assert!(error.reason().contains("SecurityExecution"));

        let contract = CapabilityContract::new(
            "package-manager",
            CapabilityOwner::AgentCore,
            vec![
                CapabilityOwner::RuntimeContracts,
                CapabilityOwner::AgentCore,
                CapabilityOwner::SecurityExecution,
                CapabilityOwner::Agentd,
            ],
            vec!["pkg.fetch.metadata", "pkg.host.install"],
            RiskClass::PrivilegedWithHumanApproval,
            OptionalDependencyBehavior::FailClosedBeforeEffectPrepared,
            "scripts/functional-capability-replay.ps1 --package",
            CapabilityOwner::SecurityExecution,
        )
        .expect("contract");

        assert!(contract.to_json().contains("\"primary_owner\":\"agent_core\""));
        assert!(!contract.to_json().contains("shell.exec"));
    }

    #[test]
    fn package_report_requires_isolation_and_rollback_before_host_mutation() {
        let denied = PackageAdapterReport::new(
            package_identity(),
            PackageAdapterPhase::Denied,
            false,
            false,
            false,
            None,
            vec!["package-denied.json"],
            Some("isolated install failed"),
        )
        .expect("failed isolated report");
        assert!(!denied.host_mutation_attempted);

        let missing_rollback = PackageAdapterReport::new(
            package_identity(),
            PackageAdapterPhase::HostPromotion,
            true,
            true,
            true,
            None,
            vec!["package-report.json"],
            Option::<String>::None,
        )
        .expect_err("rollback required");
        assert!(missing_rollback.reason().contains("rollback"));
    }

    #[test]
    fn content_report_denies_direct_tool_call_and_effect_preparation() {
        let fetch = ContentFetchContract::new(
            "doc-1",
            "https://docs.example/setup",
            "sha256:abc",
            1024,
        )
        .expect("fetch");

        let report = ContentAdapterReport::new(
            fetch.clone(),
            12,
            "sanitized: untrusted instructions removed",
            false,
            true,
            false,
        )
        .expect("report");
        assert!(report.to_json().contains("external-untrusted"));

        let error = ContentAdapterReport::new(
            fetch,
            12,
            "run shell.exec",
            true,
            true,
            false,
        )
        .expect_err("direct tool call denied");
        assert!(error.reason().contains("direct tool calls"));
    }

    #[test]
    fn firecracker_missing_dependencies_fail_before_effect_prepared() {
        let report = FirecrackerAdapterReport::new(
            "firecracker-executor",
            vec!["kvm", "firecracker-binary"],
            vec!["kvm"],
            false,
            false,
            "secret-values-redacted",
        )
        .expect("report");
        assert!(report.to_json().contains("\"missing_dependencies\":[\"kvm\"]"));
        assert!(report.to_json().contains("\"effect_prepared\":false"));

        let error = FirecrackerAdapterReport::new(
            "firecracker-executor",
            vec!["kvm"],
            vec!["kvm"],
            true,
            false,
            "secret-values-redacted",
        )
        .expect_err("missing deps cannot prepare");
        assert!(error.reason().contains("EffectPrepared"));
    }

    #[test]
    fn support_bundle_manifest_is_deterministic_and_redacted() {
        let manifest = SupportBundleManifest::new(
            "support-run-1",
            vec!["run-1"],
            "0..42",
            "sha256:feed",
            "secret-values-redacted",
            false,
        )
        .expect("manifest");
        assert!(manifest.to_json().contains("support-run-1"));

        let error = SupportBundleManifest::new(
            "support-run-1",
            vec!["run-1"],
            "0..42",
            "sha256:feed",
            "not-redacted",
            false,
        )
        .expect_err("redaction required");
        assert!(error.reason().contains("raw secrets"));
    }
}
