use crate::model::{RiskClass, contains_secret_value};

pub const ECOSYSTEM_MANIFEST_SCHEMA_VERSION: &str = "agentos.artifact-manifest.v1";
pub const REGISTRY_SNAPSHOT_SCHEMA_VERSION: &str = "agentos.registry-snapshot.v1";
pub const ECOSYSTEM_LOCK_SCHEMA_VERSION: &str = "agentos.ecosystem-lock.v1";
pub const ARTIFACT_VERIFICATION_REPORT_SCHEMA_VERSION: &str =
    "agentos.artifact-verification-report.v1";
pub const ARTIFACT_STAGING_REPORT_SCHEMA_VERSION: &str = "agentos.artifact-staging-report.v1";
pub const ACTIVATION_REPORT_SCHEMA_VERSION: &str = "agentos.artifact-activation-report.v1";
pub const ACTIVE_ARTIFACT_SET_SCHEMA_VERSION: &str = "agentos.active-artifact-set.v1";
pub const ACTIVE_ARTIFACT_REVOCATION_PROJECTION_SCHEMA_VERSION: &str =
    "agentos.active-artifact-revocation-projection.v1";
pub const COMPATIBILITY_REPORT_SCHEMA_VERSION: &str = "agentos.artifact-compatibility-report.v1";
pub const REVOCATION_ADVISORY_SCHEMA_VERSION: &str = "agentos.revocation-advisory.v1";
pub const MODEL_PROFILE_PACK_SCHEMA_VERSION: &str = "agentos.model-profile-pack.v1";
pub const KNOWLEDGE_PACK_SCHEMA_VERSION: &str = "agentos.knowledge-pack.v1";
pub const RUNTIME_ADAPTER_PACK_SCHEMA_VERSION: &str = "agentos.runtime-adapter-pack.v1";
pub const EXECUTION_IMAGE_PACK_SCHEMA_VERSION: &str = "agentos.execution-image-pack.v1";

const REQUIRED_CORE_INVARIANTS: [&str; 6] = [
    "no-shell",
    "exact-approval",
    "secret-handle",
    "source-to-sink",
    "audit",
    "rollback",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactKind {
    CapabilityPack,
    SemanticToolPack,
    PolicyPack,
    WorkflowPack,
    ModelProfilePack,
    KnowledgePack,
    RuntimeAdapterPack,
    ExecutionImagePack,
    TestReplayPack,
    TrustMetadataPack,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityPack => "capability-pack",
            Self::SemanticToolPack => "semantic-tool-pack",
            Self::PolicyPack => "policy-pack",
            Self::WorkflowPack => "workflow-pack",
            Self::ModelProfilePack => "model-profile-pack",
            Self::KnowledgePack => "knowledge-pack",
            Self::RuntimeAdapterPack => "runtime-adapter-pack",
            Self::ExecutionImagePack => "execution-image-pack",
            Self::TestReplayPack => "test-replay-pack",
            Self::TrustMetadataPack => "trust-metadata-pack",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "capability-pack" => Self::CapabilityPack,
            "semantic-tool-pack" => Self::SemanticToolPack,
            "policy-pack" => Self::PolicyPack,
            "workflow-pack" => Self::WorkflowPack,
            "model-profile-pack" => Self::ModelProfilePack,
            "knowledge-pack" => Self::KnowledgePack,
            "runtime-adapter-pack" => Self::RuntimeAdapterPack,
            "execution-image-pack" => Self::ExecutionImagePack,
            "test-replay-pack" => Self::TestReplayPack,
            "trust-metadata-pack" => Self::TrustMetadataPack,
            _ => return None,
        })
    }

    pub fn alpha_activatable(self) -> bool {
        matches!(
            self,
            Self::PolicyPack | Self::WorkflowPack | Self::TestReplayPack
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustTier {
    Core,
    Verified,
    Organization,
    Community,
    LocalDev,
}

impl TrustTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Verified => "verified",
            Self::Organization => "organization",
            Self::Community => "community",
            Self::LocalDev => "local-dev",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "core" => Self::Core,
            "verified" => Self::Verified,
            "organization" => Self::Organization,
            "community" => Self::Community,
            "local-dev" => Self::LocalDev,
            _ => return None,
        })
    }

    pub fn production_eligible(self) -> bool {
        matches!(self, Self::Core | Self::Verified | Self::Organization)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactChannel {
    Stable,
    Beta,
    Edge,
    Local,
}

impl ArtifactChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Edge => "edge",
            Self::Local => "local",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyMissingBehavior {
    BlockActivation,
    DegradeReadOnly,
}

impl DependencyMissingBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockActivation => "block-activation",
            Self::DegradeReadOnly => "degrade-read-only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModelProviderMode {
    Stub,
    Local,
    RemoteOptional,
}

impl ModelProviderMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stub => "stub",
            Self::Local => "local",
            Self::RemoteOptional => "remote-optional",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ModelRuntimeRole {
    Plan,
    Classify,
    Summarize,
    Sanitize,
}

impl ModelRuntimeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Classify => "classify",
            Self::Summarize => "summarize",
            Self::Sanitize => "sanitize",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEndpointProfile {
    pub profile_id: String,
    pub provider_mode: ModelProviderMode,
    pub provider_label: String,
    pub allowed_roles: Vec<ModelRuntimeRole>,
    pub remote_policy_gate: Option<String>,
    pub credential_handle_refs: Vec<String>,
    pub direct_provider_execution_allowed: bool,
    pub broker_required: bool,
}

impl ModelEndpointProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: impl Into<String>,
        provider_mode: ModelProviderMode,
        provider_label: impl Into<String>,
        allowed_roles: Vec<ModelRuntimeRole>,
        remote_policy_gate: Option<impl Into<String>>,
        credential_handle_refs: Vec<impl Into<String>>,
        direct_provider_execution_allowed: bool,
        broker_required: bool,
    ) -> Result<Self, EcosystemContractError> {
        let profile = Self {
            profile_id: profile_id.into(),
            provider_mode,
            provider_label: provider_label.into(),
            allowed_roles,
            remote_policy_gate: remote_policy_gate.map(Into::into),
            credential_handle_refs: credential_handle_refs.into_iter().map(Into::into).collect(),
            direct_provider_execution_allowed,
            broker_required,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_identifier_segment("model_profile.profile_id", &self.profile_id)?;
        ensure_text("model_profile.provider_label", &self.provider_label)?;
        if self.allowed_roles.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "model_profile.allowed_roles",
                reason: "model profiles must bind at least one Agent Runtime role".to_string(),
            });
        }
        if self.provider_mode == ModelProviderMode::RemoteOptional
            && self.remote_policy_gate.as_deref().unwrap_or("").is_empty()
        {
            return Err(EcosystemContractError::Invalid {
                field: "model_profile.remote_policy_gate",
                reason: "remote-optional model providers must be policy-gated".to_string(),
            });
        }
        if self.provider_mode != ModelProviderMode::RemoteOptional
            && self.remote_policy_gate.is_some()
        {
            return Err(EcosystemContractError::Invalid {
                field: "model_profile.remote_policy_gate",
                reason: "only remote-optional model providers may declare a remote policy gate"
                    .to_string(),
            });
        }
        if self.direct_provider_execution_allowed {
            return Err(EcosystemContractError::Invalid {
                field: "model_profile.direct_provider_execution_allowed",
                reason: "model profile packs cannot bypass ModelBroker".to_string(),
            });
        }
        if !self.broker_required {
            return Err(EcosystemContractError::Invalid {
                field: "model_profile.broker_required",
                reason: "model profile packs must route through ModelBroker".to_string(),
            });
        }
        if let Some(gate) = &self.remote_policy_gate {
            ensure_text("model_profile.remote_policy_gate", gate)?;
        }
        for handle in &self.credential_handle_refs {
            ensure_secret_handle("model_profile.credential_handle_refs", handle)?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut roles = self
            .allowed_roles
            .iter()
            .map(|role| role.as_str().to_string())
            .collect::<Vec<_>>();
        roles.sort();
        let mut handles = self.credential_handle_refs.clone();
        handles.sort();
        format!(
            "{{\"profile_id\":\"{}\",\"provider_mode\":\"{}\",\"provider_label\":\"{}\",\"allowed_roles\":{},\"remote_policy_gate\":{},\"credential_handle_refs\":{},\"direct_provider_execution_allowed\":{},\"broker_required\":{}}}",
            escape_json(&self.profile_id),
            self.provider_mode.as_str(),
            escape_json(&self.provider_label),
            string_array_json(&roles),
            optional_string_json(self.remote_policy_gate.as_deref()),
            string_array_json(&handles),
            self.direct_provider_execution_allowed,
            self.broker_required
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProfilePackV1 {
    pub coordinate: ArtifactCoordinate,
    pub profiles: Vec<ModelEndpointProfile>,
    pub baseline_provider_modes: Vec<ModelProviderMode>,
    pub remote_optional: bool,
    pub policy_gate_required: bool,
    pub broker_required: bool,
}

impl ModelProfilePackV1 {
    pub fn new(
        coordinate: ArtifactCoordinate,
        profiles: Vec<ModelEndpointProfile>,
        baseline_provider_modes: Vec<ModelProviderMode>,
        remote_optional: bool,
        policy_gate_required: bool,
        broker_required: bool,
    ) -> Result<Self, EcosystemContractError> {
        let pack = Self {
            coordinate,
            profiles,
            baseline_provider_modes,
            remote_optional,
            policy_gate_required,
            broker_required,
        };
        pack.validate()?;
        Ok(pack)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        if self.coordinate.kind != ArtifactKind::ModelProfilePack {
            return Err(EcosystemContractError::Invalid {
                field: "model_pack.coordinate.kind",
                reason: "model profile pack coordinate must use model-profile-pack kind"
                    .to_string(),
            });
        }
        if self.profiles.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "model_pack.profiles",
                reason: "model profile packs must define at least one profile".to_string(),
            });
        }
        if !self
            .baseline_provider_modes
            .iter()
            .any(|mode| matches!(mode, ModelProviderMode::Stub | ModelProviderMode::Local))
        {
            return Err(EcosystemContractError::Invalid {
                field: "model_pack.baseline_provider_modes",
                reason: "stub or local model provider must remain the baseline".to_string(),
            });
        }
        if self.remote_optional && !self.policy_gate_required {
            return Err(EcosystemContractError::Invalid {
                field: "model_pack.policy_gate_required",
                reason: "remote model providers are optional and must be policy-gated".to_string(),
            });
        }
        if !self.broker_required {
            return Err(EcosystemContractError::Invalid {
                field: "model_pack.broker_required",
                reason: "model profile pack activation cannot bypass ModelBroker".to_string(),
            });
        }
        for profile in &self.profiles {
            profile.validate()?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut profiles = self
            .profiles
            .iter()
            .map(ModelEndpointProfile::to_json)
            .collect::<Vec<_>>();
        profiles.sort();
        let mut baseline_modes = self
            .baseline_provider_modes
            .iter()
            .map(|mode| mode.as_str().to_string())
            .collect::<Vec<_>>();
        baseline_modes.sort();
        format!(
            "{{\"schema\":\"{}\",\"coordinate\":\"{}\",\"profiles\":[{}],\"baseline_provider_modes\":{},\"remote_optional\":{},\"policy_gate_required\":{},\"broker_required\":{}}}",
            MODEL_PROFILE_PACK_SCHEMA_VERSION,
            escape_json(&self.coordinate.as_string()),
            profiles.join(","),
            string_array_json(&baseline_modes),
            self.remote_optional,
            self.policy_gate_required,
            self.broker_required
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KnowledgeTrustLabel {
    CoreCurated,
    OrganizationCurated,
    CommunityReviewed,
    Untrusted,
    Suspicious,
}

impl KnowledgeTrustLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoreCurated => "core-curated",
            Self::OrganizationCurated => "organization-curated",
            Self::CommunityReviewed => "community-reviewed",
            Self::Untrusted => "untrusted",
            Self::Suspicious => "suspicious",
        }
    }

    pub fn requires_quarantine(self) -> bool {
        matches!(self, Self::Untrusted | Self::Suspicious)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryScope {
    PlannerContext,
    RunScoped,
    Quarantined,
}

impl MemoryScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlannerContext => "planner-context",
            Self::RunScoped => "run-scoped",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeSourceV1 {
    pub source_id: String,
    pub provenance_uri: String,
    pub content_digest: String,
    pub trust_label: KnowledgeTrustLabel,
    pub ttl_seconds: u64,
    pub allowed_memory_scope: MemoryScope,
    pub quarantined: bool,
    pub bounded_context_bytes: u64,
}

impl KnowledgeSourceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_id: impl Into<String>,
        provenance_uri: impl Into<String>,
        content_digest: impl Into<String>,
        trust_label: KnowledgeTrustLabel,
        ttl_seconds: u64,
        allowed_memory_scope: MemoryScope,
        quarantined: bool,
        bounded_context_bytes: u64,
    ) -> Result<Self, EcosystemContractError> {
        let source = Self {
            source_id: source_id.into(),
            provenance_uri: provenance_uri.into(),
            content_digest: content_digest.into(),
            trust_label,
            ttl_seconds,
            allowed_memory_scope,
            quarantined,
            bounded_context_bytes,
        };
        source.validate()?;
        Ok(source)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_identifier_segment("knowledge.source_id", &self.source_id)?;
        ensure_text("knowledge.provenance_uri", &self.provenance_uri)?;
        ensure_digest("knowledge.content_digest", &self.content_digest)?;
        if self.ttl_seconds == 0 {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge.ttl_seconds",
                reason: "knowledge source TTL must be positive".to_string(),
            });
        }
        if self.bounded_context_bytes == 0 {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge.bounded_context_bytes",
                reason: "knowledge source must declare bounded planner context bytes".to_string(),
            });
        }
        if self.trust_label.requires_quarantine()
            && (!self.quarantined || self.allowed_memory_scope != MemoryScope::Quarantined)
        {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge.quarantined",
                reason: "untrusted or suspicious knowledge must remain quarantined".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"source_id\":\"{}\",\"provenance_uri\":\"{}\",\"content_digest\":\"{}\",\"trust_label\":\"{}\",\"ttl_seconds\":{},\"allowed_memory_scope\":\"{}\",\"quarantined\":{},\"bounded_context_bytes\":{}}}",
            escape_json(&self.source_id),
            escape_json(&self.provenance_uri),
            escape_json(&self.content_digest),
            self.trust_label.as_str(),
            self.ttl_seconds,
            self.allowed_memory_scope.as_str(),
            self.quarantined,
            self.bounded_context_bytes
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgePackV1 {
    pub coordinate: ArtifactCoordinate,
    pub sources: Vec<KnowledgeSourceV1>,
    pub planner_context_bounded: bool,
    pub source_labels_required: bool,
    pub approval_claims_allowed: bool,
    pub privileged_policy_instructions_allowed: bool,
}

impl KnowledgePackV1 {
    pub fn new(
        coordinate: ArtifactCoordinate,
        sources: Vec<KnowledgeSourceV1>,
        planner_context_bounded: bool,
        source_labels_required: bool,
        approval_claims_allowed: bool,
        privileged_policy_instructions_allowed: bool,
    ) -> Result<Self, EcosystemContractError> {
        let pack = Self {
            coordinate,
            sources,
            planner_context_bounded,
            source_labels_required,
            approval_claims_allowed,
            privileged_policy_instructions_allowed,
        };
        pack.validate()?;
        Ok(pack)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        if self.coordinate.kind != ArtifactKind::KnowledgePack {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge_pack.coordinate.kind",
                reason: "knowledge pack coordinate must use knowledge-pack kind".to_string(),
            });
        }
        if self.sources.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge_pack.sources",
                reason: "knowledge packs must bind at least one source".to_string(),
            });
        }
        if !self.planner_context_bounded {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge_pack.planner_context_bounded",
                reason: "knowledge entering planner context must be bounded".to_string(),
            });
        }
        if !self.source_labels_required {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge_pack.source_labels_required",
                reason: "knowledge entering planner context must remain source-labeled".to_string(),
            });
        }
        if self.approval_claims_allowed {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge_pack.approval_claims_allowed",
                reason: "knowledge packs cannot create approval claims".to_string(),
            });
        }
        if self.privileged_policy_instructions_allowed {
            return Err(EcosystemContractError::Invalid {
                field: "knowledge_pack.privileged_policy_instructions_allowed",
                reason: "knowledge packs cannot write privileged policy instructions".to_string(),
            });
        }
        for source in &self.sources {
            source.validate()?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut sources = self
            .sources
            .iter()
            .map(KnowledgeSourceV1::to_json)
            .collect::<Vec<_>>();
        sources.sort();
        format!(
            "{{\"schema\":\"{}\",\"coordinate\":\"{}\",\"sources\":[{}],\"planner_context_bounded\":{},\"source_labels_required\":{},\"approval_claims_allowed\":{},\"privileged_policy_instructions_allowed\":{}}}",
            KNOWLEDGE_PACK_SCHEMA_VERSION,
            escape_json(&self.coordinate.as_string()),
            sources.join(","),
            self.planner_context_bounded,
            self.source_labels_required,
            self.approval_claims_allowed,
            self.privileged_policy_instructions_allowed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAdapterToolBinding {
    pub tool_name: String,
    pub risk_class: RiskClass,
    pub policy_mapping: String,
    pub required_dependency_features: Vec<String>,
    pub optional_dependency_features: Vec<String>,
    pub missing_optional_behavior: DependencyMissingBehavior,
}

impl RuntimeAdapterToolBinding {
    pub fn new(
        tool_name: impl Into<String>,
        risk_class: RiskClass,
        policy_mapping: impl Into<String>,
        required_dependency_features: Vec<impl Into<String>>,
        optional_dependency_features: Vec<impl Into<String>>,
        missing_optional_behavior: DependencyMissingBehavior,
    ) -> Result<Self, EcosystemContractError> {
        let binding = Self {
            tool_name: tool_name.into(),
            risk_class,
            policy_mapping: policy_mapping.into(),
            required_dependency_features: required_dependency_features
                .into_iter()
                .map(Into::into)
                .collect(),
            optional_dependency_features: optional_dependency_features
                .into_iter()
                .map(Into::into)
                .collect(),
            missing_optional_behavior,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_semantic_tool_name("adapter.tool_name", &self.tool_name)?;
        ensure_text("adapter.policy_mapping", &self.policy_mapping)?;
        if is_shell_surface(&self.tool_name) {
            return Err(EcosystemContractError::Invalid {
                field: "adapter.tool_name",
                reason: "adapter packs cannot expose arbitrary shell".to_string(),
            });
        }
        if self.risk_class == RiskClass::Never {
            return Err(EcosystemContractError::Invalid {
                field: "adapter.risk_class",
                reason: "adapter tools must map to an executable policy risk class".to_string(),
            });
        }
        if self.missing_optional_behavior != DependencyMissingBehavior::DegradeReadOnly {
            return Err(EcosystemContractError::Invalid {
                field: "adapter.missing_optional_behavior",
                reason: "missing optional adapter dependencies must degrade before effects"
                    .to_string(),
            });
        }
        for feature in self
            .required_dependency_features
            .iter()
            .chain(self.optional_dependency_features.iter())
        {
            ensure_text("adapter.dependency_feature", feature)?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut required = self.required_dependency_features.clone();
        required.sort();
        let mut optional = self.optional_dependency_features.clone();
        optional.sort();
        format!(
            "{{\"tool_name\":\"{}\",\"risk_class\":\"{}\",\"policy_mapping\":\"{}\",\"required_dependency_features\":{},\"optional_dependency_features\":{},\"missing_optional_behavior\":\"{}\"}}",
            escape_json(&self.tool_name),
            self.risk_class.as_str(),
            escape_json(&self.policy_mapping),
            string_array_json(&required),
            string_array_json(&optional),
            self.missing_optional_behavior.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAdapterPackV1 {
    pub coordinate: ArtifactCoordinate,
    pub tool_bindings: Vec<RuntimeAdapterToolBinding>,
    pub requires_security_execution_engine: bool,
    pub direct_host_mutation_allowed: bool,
    pub replay_evidence_required: bool,
}

impl RuntimeAdapterPackV1 {
    pub fn new(
        coordinate: ArtifactCoordinate,
        tool_bindings: Vec<RuntimeAdapterToolBinding>,
        requires_security_execution_engine: bool,
        direct_host_mutation_allowed: bool,
        replay_evidence_required: bool,
    ) -> Result<Self, EcosystemContractError> {
        let pack = Self {
            coordinate,
            tool_bindings,
            requires_security_execution_engine,
            direct_host_mutation_allowed,
            replay_evidence_required,
        };
        pack.validate()?;
        Ok(pack)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        if self.coordinate.kind != ArtifactKind::RuntimeAdapterPack {
            return Err(EcosystemContractError::Invalid {
                field: "adapter_pack.coordinate.kind",
                reason: "runtime adapter pack coordinate must use runtime-adapter-pack kind"
                    .to_string(),
            });
        }
        if self.tool_bindings.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "adapter_pack.tool_bindings",
                reason: "runtime adapter pack must declare semantic tools".to_string(),
            });
        }
        if !self.requires_security_execution_engine {
            return Err(EcosystemContractError::Invalid {
                field: "adapter_pack.requires_security_execution_engine",
                reason: "adapter side effects must go through SecurityExecutionEngine".to_string(),
            });
        }
        if self.direct_host_mutation_allowed {
            return Err(EcosystemContractError::Invalid {
                field: "adapter_pack.direct_host_mutation_allowed",
                reason: "adapter pack cannot mutate host state directly".to_string(),
            });
        }
        if !self.replay_evidence_required {
            return Err(EcosystemContractError::Invalid {
                field: "adapter_pack.replay_evidence_required",
                reason: "adapter activation requires replay evidence".to_string(),
            });
        }
        for binding in &self.tool_bindings {
            binding.validate()?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut bindings = self
            .tool_bindings
            .iter()
            .map(RuntimeAdapterToolBinding::to_json)
            .collect::<Vec<_>>();
        bindings.sort();
        format!(
            "{{\"schema\":\"{}\",\"coordinate\":\"{}\",\"tool_bindings\":[{}],\"requires_security_execution_engine\":{},\"direct_host_mutation_allowed\":{},\"replay_evidence_required\":{}}}",
            RUNTIME_ADAPTER_PACK_SCHEMA_VERSION,
            escape_json(&self.coordinate.as_string()),
            bindings.join(","),
            self.requires_security_execution_engine,
            self.direct_host_mutation_allowed,
            self.replay_evidence_required
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionImagePackV1 {
    pub coordinate: ArtifactCoordinate,
    pub kernel_digest: String,
    pub rootfs_digest: String,
    pub image_digest: String,
    pub provenance_digest: String,
    pub compatibility: CompatibilityRequirement,
    pub firecracker_dependency: ArtifactDependency,
    pub kvm_required: bool,
    pub host_fallback_allowed: bool,
    pub active_artifact_set_hash_required: bool,
    pub rollback_rule: String,
}

impl ExecutionImagePackV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinate: ArtifactCoordinate,
        kernel_digest: impl Into<String>,
        rootfs_digest: impl Into<String>,
        image_digest: impl Into<String>,
        provenance_digest: impl Into<String>,
        compatibility: CompatibilityRequirement,
        firecracker_dependency: ArtifactDependency,
        kvm_required: bool,
        host_fallback_allowed: bool,
        active_artifact_set_hash_required: bool,
        rollback_rule: impl Into<String>,
    ) -> Result<Self, EcosystemContractError> {
        let pack = Self {
            coordinate,
            kernel_digest: kernel_digest.into(),
            rootfs_digest: rootfs_digest.into(),
            image_digest: image_digest.into(),
            provenance_digest: provenance_digest.into(),
            compatibility,
            firecracker_dependency,
            kvm_required,
            host_fallback_allowed,
            active_artifact_set_hash_required,
            rollback_rule: rollback_rule.into(),
        };
        pack.validate()?;
        Ok(pack)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        if self.coordinate.kind != ArtifactKind::ExecutionImagePack {
            return Err(EcosystemContractError::Invalid {
                field: "image_pack.coordinate.kind",
                reason: "execution image pack coordinate must use execution-image-pack kind"
                    .to_string(),
            });
        }
        ensure_digest("image_pack.kernel_digest", &self.kernel_digest)?;
        ensure_digest("image_pack.rootfs_digest", &self.rootfs_digest)?;
        ensure_digest("image_pack.image_digest", &self.image_digest)?;
        ensure_digest("image_pack.provenance_digest", &self.provenance_digest)?;
        self.compatibility.validate()?;
        self.firecracker_dependency.validate()?;
        if !self.firecracker_dependency.optional
            || self.firecracker_dependency.missing_behavior
                != DependencyMissingBehavior::DegradeReadOnly
        {
            return Err(EcosystemContractError::Invalid {
                field: "image_pack.firecracker_dependency",
                reason: "Firecracker dependency must be optional but fail closed into read-only degradation"
                    .to_string(),
            });
        }
        if !self.kvm_required {
            return Err(EcosystemContractError::Invalid {
                field: "image_pack.kvm_required",
                reason: "execution image activation must account for KVM availability".to_string(),
            });
        }
        if self.host_fallback_allowed {
            return Err(EcosystemContractError::Invalid {
                field: "image_pack.host_fallback_allowed",
                reason: "missing virtualization cannot fall back to host execution".to_string(),
            });
        }
        if !self.active_artifact_set_hash_required {
            return Err(EcosystemContractError::Invalid {
                field: "image_pack.active_artifact_set_hash_required",
                reason: "update bundles must account for the active artifact set".to_string(),
            });
        }
        ensure_text("image_pack.rollback_rule", &self.rollback_rule)?;
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"coordinate\":\"{}\",\"kernel_digest\":\"{}\",\"rootfs_digest\":\"{}\",\"image_digest\":\"{}\",\"provenance_digest\":\"{}\",\"compatibility\":{},\"firecracker_dependency\":{},\"kvm_required\":{},\"host_fallback_allowed\":{},\"active_artifact_set_hash_required\":{},\"rollback_rule\":\"{}\"}}",
            EXECUTION_IMAGE_PACK_SCHEMA_VERSION,
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.kernel_digest),
            escape_json(&self.rootfs_digest),
            escape_json(&self.image_digest),
            escape_json(&self.provenance_digest),
            self.compatibility.to_json(),
            self.firecracker_dependency.to_json(),
            self.kvm_required,
            self.host_fallback_allowed,
            self.active_artifact_set_hash_required,
            escape_json(&self.rollback_rule)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtifactCoordinate {
    pub kind: ArtifactKind,
    pub publisher: String,
    pub name: String,
    pub version: String,
}

impl ArtifactCoordinate {
    pub fn new(
        kind: ArtifactKind,
        publisher: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, EcosystemContractError> {
        let coordinate = Self {
            kind,
            publisher: publisher.into(),
            name: name.into(),
            version: version.into(),
        };
        coordinate.validate()?;
        Ok(coordinate)
    }

    pub fn parse(value: &str) -> Result<Self, EcosystemContractError> {
        let rest =
            value
                .strip_prefix("agentos:")
                .ok_or_else(|| EcosystemContractError::Invalid {
                    field: "coordinate",
                    reason: "coordinate must start with agentos:".to_string(),
                })?;
        let (path, version) =
            rest.rsplit_once('@')
                .ok_or_else(|| EcosystemContractError::Invalid {
                    field: "coordinate",
                    reason: "coordinate must include @version".to_string(),
                })?;
        let parts = path.split('/').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(EcosystemContractError::Invalid {
                field: "coordinate",
                reason: "coordinate must be agentos:<kind>/<publisher>/<name>@<version>"
                    .to_string(),
            });
        }
        let kind =
            ArtifactKind::from_str(parts[0]).ok_or_else(|| EcosystemContractError::Invalid {
                field: "coordinate.kind",
                reason: "artifact kind is not recognized".to_string(),
            })?;
        Self::new(kind, parts[1], parts[2], version)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_identifier_segment("coordinate.publisher", &self.publisher)?;
        ensure_identifier_segment("coordinate.name", &self.name)?;
        ensure_text("coordinate.version", &self.version)?;
        if !is_semver_like(&self.version) {
            return Err(EcosystemContractError::Invalid {
                field: "coordinate.version",
                reason: "artifact version must be semver-like".to_string(),
            });
        }
        Ok(())
    }

    pub fn as_string(&self) -> String {
        format!(
            "agentos:{}/{}/{}@{}",
            self.kind.as_str(),
            self.publisher,
            self.name,
            self.version
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"coordinate\":\"{}\",\"kind\":\"{}\",\"publisher\":\"{}\",\"name\":\"{}\",\"version\":\"{}\"}}",
            escape_json(&self.as_string()),
            self.kind.as_str(),
            escape_json(&self.publisher),
            escape_json(&self.name),
            escape_json(&self.version)
        )
    }
}

impl std::fmt::Display for ArtifactCoordinate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.as_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDependency {
    pub coordinate: ArtifactCoordinate,
    pub optional: bool,
    pub missing_behavior: DependencyMissingBehavior,
    pub allows_host_mutation_when_missing: bool,
}

impl ArtifactDependency {
    pub fn required(coordinate: ArtifactCoordinate) -> Result<Self, EcosystemContractError> {
        Self::new(
            coordinate,
            false,
            DependencyMissingBehavior::BlockActivation,
            false,
        )
    }

    pub fn optional_read_only(
        coordinate: ArtifactCoordinate,
    ) -> Result<Self, EcosystemContractError> {
        Self::new(
            coordinate,
            true,
            DependencyMissingBehavior::DegradeReadOnly,
            false,
        )
    }

    pub fn new(
        coordinate: ArtifactCoordinate,
        optional: bool,
        missing_behavior: DependencyMissingBehavior,
        allows_host_mutation_when_missing: bool,
    ) -> Result<Self, EcosystemContractError> {
        let dependency = Self {
            coordinate,
            optional,
            missing_behavior,
            allows_host_mutation_when_missing,
        };
        dependency.validate()?;
        Ok(dependency)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        if !self.optional && self.missing_behavior != DependencyMissingBehavior::BlockActivation {
            return Err(EcosystemContractError::Invalid {
                field: "dependency.missing_behavior",
                reason: "required dependencies must block activation when missing".to_string(),
            });
        }
        if self.allows_host_mutation_when_missing {
            return Err(EcosystemContractError::Invalid {
                field: "dependency.allows_host_mutation_when_missing",
                reason: "missing dependencies cannot fall back to host mutation".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"coordinate\":\"{}\",\"optional\":{},\"missing_behavior\":\"{}\",\"allows_host_mutation_when_missing\":{}}}",
            escape_json(&self.coordinate.as_string()),
            self.optional,
            self.missing_behavior.as_str(),
            self.allows_host_mutation_when_missing
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactFile {
    pub path: String,
    pub digest: String,
    pub bytes: u64,
    pub executable: bool,
}

impl ArtifactFile {
    pub fn new(
        path: impl Into<String>,
        digest: impl Into<String>,
        bytes: u64,
        executable: bool,
    ) -> Result<Self, EcosystemContractError> {
        let file = Self {
            path: path.into(),
            digest: digest.into(),
            bytes,
            executable,
        };
        file.validate()?;
        Ok(file)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_relative_artifact_path("file.path", &self.path)?;
        ensure_digest("file.digest", &self.digest)?;
        if self.bytes == 0 {
            return Err(EcosystemContractError::Invalid {
                field: "file.bytes",
                reason: "artifact files must declare a positive byte size".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"path\":\"{}\",\"digest\":\"{}\",\"bytes\":{},\"executable\":{}}}",
            escape_json(&self.path),
            escape_json(&self.digest),
            self.bytes,
            self.executable
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationRequirement {
    pub requires_agent_core_plan_spec: bool,
    pub requires_security_execution_engine: bool,
    pub requires_exact_approval: bool,
    pub required_policy_version: String,
    pub preserved_core_invariants: Vec<String>,
    pub required_runtime_capabilities: Vec<String>,
}

impl ActivationRequirement {
    pub fn production_default(
        required_policy_version: impl Into<String>,
    ) -> Result<Self, EcosystemContractError> {
        Self::new(
            true,
            true,
            true,
            required_policy_version,
            REQUIRED_CORE_INVARIANTS,
            ["audit-journal", "rollback-store"],
        )
    }

    pub fn new(
        requires_agent_core_plan_spec: bool,
        requires_security_execution_engine: bool,
        requires_exact_approval: bool,
        required_policy_version: impl Into<String>,
        preserved_core_invariants: impl IntoIterator<Item = impl Into<String>>,
        required_runtime_capabilities: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, EcosystemContractError> {
        let requirement = Self {
            requires_agent_core_plan_spec,
            requires_security_execution_engine,
            requires_exact_approval,
            required_policy_version: required_policy_version.into(),
            preserved_core_invariants: preserved_core_invariants
                .into_iter()
                .map(Into::into)
                .collect(),
            required_runtime_capabilities: required_runtime_capabilities
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        requirement.validate()?;
        Ok(requirement)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text(
            "activation.required_policy_version",
            &self.required_policy_version,
        )?;
        if !self.requires_agent_core_plan_spec {
            return Err(EcosystemContractError::Invalid {
                field: "activation.requires_agent_core_plan_spec",
                reason: "artifact activation must be expressed as an AgentCore PlanSpec"
                    .to_string(),
            });
        }
        if !self.requires_security_execution_engine {
            return Err(EcosystemContractError::Invalid {
                field: "activation.requires_security_execution_engine",
                reason: "artifact activation side effects must go through SecurityExecutionEngine"
                    .to_string(),
            });
        }
        if !self.requires_exact_approval {
            return Err(EcosystemContractError::Invalid {
                field: "activation.requires_exact_approval",
                reason: "artifact activation must preserve exact approval".to_string(),
            });
        }
        for invariant in REQUIRED_CORE_INVARIANTS {
            if !self
                .preserved_core_invariants
                .iter()
                .any(|value| value == invariant)
            {
                return Err(EcosystemContractError::Invalid {
                    field: "activation.preserved_core_invariants",
                    reason: format!("activation must preserve core invariant {invariant}"),
                });
            }
        }
        for value in self
            .preserved_core_invariants
            .iter()
            .chain(self.required_runtime_capabilities.iter())
        {
            ensure_text("activation.requirement", value)?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut invariants = self.preserved_core_invariants.clone();
        invariants.sort();
        let mut capabilities = self.required_runtime_capabilities.clone();
        capabilities.sort();
        format!(
            "{{\"requires_agent_core_plan_spec\":{},\"requires_security_execution_engine\":{},\"requires_exact_approval\":{},\"required_policy_version\":\"{}\",\"preserved_core_invariants\":{},\"required_runtime_capabilities\":{}}}",
            self.requires_agent_core_plan_spec,
            self.requires_security_execution_engine,
            self.requires_exact_approval,
            escape_json(&self.required_policy_version),
            string_array_json(&invariants),
            string_array_json(&capabilities)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactTrust {
    pub tier: TrustTier,
    pub signed_by: Option<String>,
    pub provenance_digest: Option<String>,
    pub sbom_digest: Option<String>,
    pub release_gate_digest: Option<String>,
    pub production_promotable: bool,
}

impl ArtifactTrust {
    pub fn new(
        tier: TrustTier,
        signed_by: Option<impl Into<String>>,
        provenance_digest: Option<impl Into<String>>,
        sbom_digest: Option<impl Into<String>>,
        release_gate_digest: Option<impl Into<String>>,
        production_promotable: bool,
    ) -> Result<Self, EcosystemContractError> {
        let trust = Self {
            tier,
            signed_by: signed_by.map(Into::into),
            provenance_digest: provenance_digest.map(Into::into),
            sbom_digest: sbom_digest.map(Into::into),
            release_gate_digest: release_gate_digest.map(Into::into),
            production_promotable,
        };
        trust.validate()?;
        Ok(trust)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        if self.production_promotable && !self.tier.production_eligible() {
            return Err(EcosystemContractError::Invalid {
                field: "trust.production_promotable",
                reason:
                    "community and local-dev artifacts are not production-promotable by default"
                        .to_string(),
            });
        }
        if self.production_promotable {
            if self.signed_by.as_deref().unwrap_or("").is_empty() {
                return Err(EcosystemContractError::Invalid {
                    field: "trust.signed_by",
                    reason: "production-promotable artifacts must be signed".to_string(),
                });
            }
            if self.provenance_digest.as_deref().unwrap_or("").is_empty() {
                return Err(EcosystemContractError::Invalid {
                    field: "trust.provenance_digest",
                    reason: "production-promotable artifacts must bind provenance".to_string(),
                });
            }
        }
        if self.tier == TrustTier::Core
            && self.release_gate_digest.as_deref().unwrap_or("").is_empty()
        {
            return Err(EcosystemContractError::Invalid {
                field: "trust.release_gate_digest",
                reason: "core artifacts must be covered by a release gate".to_string(),
            });
        }
        if let Some(signed_by) = &self.signed_by {
            ensure_text("trust.signed_by", signed_by)?;
        }
        for (field, value) in [
            ("trust.provenance_digest", self.provenance_digest.as_deref()),
            ("trust.sbom_digest", self.sbom_digest.as_deref()),
            (
                "trust.release_gate_digest",
                self.release_gate_digest.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                ensure_digest(field, value)?;
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"tier\":\"{}\",\"signed_by\":{},\"provenance_digest\":{},\"sbom_digest\":{},\"release_gate_digest\":{},\"production_promotable\":{}}}",
            self.tier.as_str(),
            optional_string_json(self.signed_by.as_deref()),
            optional_string_json(self.provenance_digest.as_deref()),
            optional_string_json(self.sbom_digest.as_deref()),
            optional_string_json(self.release_gate_digest.as_deref()),
            self.production_promotable
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityRequirement {
    pub min_runtime_contract_version: String,
    pub max_runtime_contract_version: String,
    pub architectures: Vec<String>,
    pub required_host_features: Vec<String>,
    pub optional_host_features: Vec<String>,
    pub migration_rules: Vec<MigrationRule>,
}

impl CompatibilityRequirement {
    pub fn new(
        min_runtime_contract_version: impl Into<String>,
        max_runtime_contract_version: impl Into<String>,
        architectures: Vec<impl Into<String>>,
        required_host_features: Vec<impl Into<String>>,
        optional_host_features: Vec<impl Into<String>>,
        migration_rules: Vec<MigrationRule>,
    ) -> Result<Self, EcosystemContractError> {
        let requirement = Self {
            min_runtime_contract_version: min_runtime_contract_version.into(),
            max_runtime_contract_version: max_runtime_contract_version.into(),
            architectures: architectures.into_iter().map(Into::into).collect(),
            required_host_features: required_host_features.into_iter().map(Into::into).collect(),
            optional_host_features: optional_host_features.into_iter().map(Into::into).collect(),
            migration_rules,
        };
        requirement.validate()?;
        Ok(requirement)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_semver(
            "compatibility.min_runtime_contract_version",
            &self.min_runtime_contract_version,
        )?;
        ensure_semver(
            "compatibility.max_runtime_contract_version",
            &self.max_runtime_contract_version,
        )?;
        if compare_semver(
            &self.min_runtime_contract_version,
            &self.max_runtime_contract_version,
        ) == Some(std::cmp::Ordering::Greater)
        {
            return Err(EcosystemContractError::Invalid {
                field: "compatibility.runtime_contract_version",
                reason: "minimum runtime contract version cannot exceed maximum".to_string(),
            });
        }
        if self.architectures.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "compatibility.architectures",
                reason: "compatibility must declare supported architectures".to_string(),
            });
        }
        for value in self
            .architectures
            .iter()
            .chain(self.required_host_features.iter())
            .chain(self.optional_host_features.iter())
        {
            ensure_text("compatibility.value", value)?;
        }
        for rule in &self.migration_rules {
            rule.validate()?;
        }
        Ok(())
    }

    pub fn evaluate(
        &self,
        coordinate: ArtifactCoordinate,
        runtime_contract_version: impl Into<String>,
        architecture: impl Into<String>,
        host_features: Vec<impl Into<String>>,
        downgrade_requested: bool,
        rollback_contract: Option<impl Into<String>>,
    ) -> Result<CompatibilityValidationReportV1, EcosystemContractError> {
        self.validate()?;
        let runtime_contract_version = runtime_contract_version.into();
        let architecture = architecture.into();
        let host_features = host_features
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let rollback_contract = rollback_contract.map(Into::into);
        let supported_runtime = runtime_in_range(
            &runtime_contract_version,
            &self.min_runtime_contract_version,
            &self.max_runtime_contract_version,
        );
        let supported_architecture = self
            .architectures
            .iter()
            .any(|value| value == &architecture);
        let missing_required_features =
            missing_values(&self.required_host_features, &host_features);
        let missing_optional_features =
            missing_values(&self.optional_host_features, &host_features);
        let downgrade_without_rollback = downgrade_requested && rollback_contract.is_none();
        let can_activate = supported_runtime
            && supported_architecture
            && missing_required_features.is_empty()
            && !downgrade_without_rollback;
        CompatibilityValidationReportV1::new(
            coordinate,
            runtime_contract_version,
            architecture,
            supported_runtime,
            supported_architecture,
            missing_required_features,
            missing_optional_features,
            downgrade_requested,
            rollback_contract,
            can_activate,
        )
    }

    pub fn to_json(&self) -> String {
        let mut architectures = self.architectures.clone();
        architectures.sort();
        let mut required = self.required_host_features.clone();
        required.sort();
        let mut optional = self.optional_host_features.clone();
        optional.sort();
        let mut migrations = self
            .migration_rules
            .iter()
            .map(MigrationRule::to_json)
            .collect::<Vec<_>>();
        migrations.sort();
        format!(
            "{{\"min_runtime_contract_version\":\"{}\",\"max_runtime_contract_version\":\"{}\",\"architectures\":{},\"required_host_features\":{},\"optional_host_features\":{},\"migration_rules\":[{}]}}",
            escape_json(&self.min_runtime_contract_version),
            escape_json(&self.max_runtime_contract_version),
            string_array_json(&architectures),
            string_array_json(&required),
            string_array_json(&optional),
            migrations.join(",")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRule {
    pub from_version: String,
    pub to_version: String,
    pub rollback_contract: Option<String>,
}

impl MigrationRule {
    pub fn new(
        from_version: impl Into<String>,
        to_version: impl Into<String>,
        rollback_contract: Option<impl Into<String>>,
    ) -> Result<Self, EcosystemContractError> {
        let rule = Self {
            from_version: from_version.into(),
            to_version: to_version.into(),
            rollback_contract: rollback_contract.map(Into::into),
        };
        rule.validate()?;
        Ok(rule)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_semver("migration.from_version", &self.from_version)?;
        ensure_semver("migration.to_version", &self.to_version)?;
        if compare_semver(&self.from_version, &self.to_version) == Some(std::cmp::Ordering::Greater)
            && self.rollback_contract.as_deref().unwrap_or("").is_empty()
        {
            return Err(EcosystemContractError::Invalid {
                field: "migration.rollback_contract",
                reason: "downgrade migrations require an explicit rollback contract".to_string(),
            });
        }
        if let Some(rollback_contract) = &self.rollback_contract {
            ensure_text("migration.rollback_contract", rollback_contract)?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"from_version\":\"{}\",\"to_version\":\"{}\",\"rollback_contract\":{}}}",
            escape_json(&self.from_version),
            escape_json(&self.to_version),
            optional_string_json(self.rollback_contract.as_deref())
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOsArtifactManifestV1 {
    pub coordinate: ArtifactCoordinate,
    pub artifact_digest: String,
    pub runtime_contract_version: String,
    pub compatibility: CompatibilityRequirement,
    pub dependencies: Vec<ArtifactDependency>,
    pub files: Vec<ArtifactFile>,
    pub activation: ActivationRequirement,
    pub trust: ArtifactTrust,
    pub local_replay: String,
    pub unknown_required_fields: Vec<String>,
}

impl AgentOsArtifactManifestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinate: ArtifactCoordinate,
        artifact_digest: impl Into<String>,
        runtime_contract_version: impl Into<String>,
        compatibility: CompatibilityRequirement,
        dependencies: Vec<ArtifactDependency>,
        files: Vec<ArtifactFile>,
        activation: ActivationRequirement,
        trust: ArtifactTrust,
        local_replay: impl Into<String>,
        unknown_required_fields: Vec<impl Into<String>>,
    ) -> Result<Self, EcosystemContractError> {
        let manifest = Self {
            coordinate,
            artifact_digest: artifact_digest.into(),
            runtime_contract_version: runtime_contract_version.into(),
            compatibility,
            dependencies,
            files,
            activation,
            trust,
            local_replay: local_replay.into(),
            unknown_required_fields: unknown_required_fields
                .into_iter()
                .map(Into::into)
                .collect(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        ensure_digest("manifest.artifact_digest", &self.artifact_digest)?;
        ensure_semver(
            "manifest.runtime_contract_version",
            &self.runtime_contract_version,
        )?;
        self.compatibility.validate()?;
        self.activation.validate()?;
        self.trust.validate()?;
        ensure_text("manifest.local_replay", &self.local_replay)?;
        if !self.unknown_required_fields.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "manifest.unknown_required_fields",
                reason: "unknown required fields must be rejected".to_string(),
            });
        }
        if self.files.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "manifest.files",
                reason: "artifact manifest must bind at least one file".to_string(),
            });
        }
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        for file in &self.files {
            file.validate()?;
        }
        Ok(())
    }

    pub fn validate_for_alpha_activation(&self) -> Result<(), EcosystemContractError> {
        self.validate()?;
        if !self.coordinate.kind.alpha_activatable() {
            return Err(EcosystemContractError::Invalid {
                field: "manifest.coordinate.kind",
                reason: "only policy-pack, workflow-pack and test-replay-pack activate in alpha"
                    .to_string(),
            });
        }
        Ok(())
    }

    pub fn stable_fingerprint(&self) -> String {
        stable_contract_hash(&self.to_json())
    }

    pub fn to_json(&self) -> String {
        let mut dependencies = self
            .dependencies
            .iter()
            .map(ArtifactDependency::to_json)
            .collect::<Vec<_>>();
        dependencies.sort();
        let mut files = self
            .files
            .iter()
            .map(ArtifactFile::to_json)
            .collect::<Vec<_>>();
        files.sort();
        format!(
            "{{\"schema\":\"{}\",\"coordinate\":\"{}\",\"artifact_digest\":\"{}\",\"runtime_contract_version\":\"{}\",\"compatibility\":{},\"dependencies\":[{}],\"files\":[{}],\"activation\":{},\"trust\":{},\"local_replay\":\"{}\",\"unknown_required_fields\":{}}}",
            ECOSYSTEM_MANIFEST_SCHEMA_VERSION,
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.artifact_digest),
            escape_json(&self.runtime_contract_version),
            self.compatibility.to_json(),
            dependencies.join(","),
            files.join(","),
            self.activation.to_json(),
            self.trust.to_json(),
            escape_json(&self.local_replay),
            string_array_json(&self.unknown_required_fields)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryArtifactEntry {
    pub coordinate: ArtifactCoordinate,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub trust: ArtifactTrust,
    pub channel: ArtifactChannel,
    pub source_uri: Option<String>,
    pub revoked: bool,
    pub advisory_refs: Vec<String>,
}

impl RegistryArtifactEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinate: ArtifactCoordinate,
        manifest_digest: impl Into<String>,
        artifact_digest: impl Into<String>,
        trust: ArtifactTrust,
        channel: ArtifactChannel,
        source_uri: Option<impl Into<String>>,
        revoked: bool,
        advisory_refs: Vec<impl Into<String>>,
    ) -> Result<Self, EcosystemContractError> {
        let entry = Self {
            coordinate,
            manifest_digest: manifest_digest.into(),
            artifact_digest: artifact_digest.into(),
            trust,
            channel,
            source_uri: source_uri.map(Into::into),
            revoked,
            advisory_refs: advisory_refs.into_iter().map(Into::into).collect(),
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        ensure_digest("registry.manifest_digest", &self.manifest_digest)?;
        ensure_digest("registry.artifact_digest", &self.artifact_digest)?;
        self.trust.validate()?;
        if let Some(source_uri) = &self.source_uri {
            ensure_text("registry.source_uri", source_uri)?;
        }
        for advisory in &self.advisory_refs {
            ensure_text("registry.advisory_ref", advisory)?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut advisory_refs = self.advisory_refs.clone();
        advisory_refs.sort();
        format!(
            "{{\"coordinate\":\"{}\",\"manifest_digest\":\"{}\",\"artifact_digest\":\"{}\",\"trust\":{},\"channel\":\"{}\",\"source_uri\":{},\"revoked\":{},\"advisory_refs\":{}}}",
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.manifest_digest),
            escape_json(&self.artifact_digest),
            self.trust.to_json(),
            self.channel.as_str(),
            optional_string_json(self.source_uri.as_deref()),
            self.revoked,
            string_array_json(&advisory_refs)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationAdvisoryV1 {
    pub advisory_id: String,
    pub coordinate: ArtifactCoordinate,
    pub artifact_digest: String,
    pub severity: String,
    pub reason: String,
    pub published_at: String,
    pub superseded_by: Option<ArtifactCoordinate>,
}

impl RevocationAdvisoryV1 {
    pub fn new(
        advisory_id: impl Into<String>,
        coordinate: ArtifactCoordinate,
        artifact_digest: impl Into<String>,
        severity: impl Into<String>,
        reason: impl Into<String>,
        published_at: impl Into<String>,
        superseded_by: Option<ArtifactCoordinate>,
    ) -> Result<Self, EcosystemContractError> {
        let advisory = Self {
            advisory_id: advisory_id.into(),
            coordinate,
            artifact_digest: artifact_digest.into(),
            severity: severity.into(),
            reason: reason.into(),
            published_at: published_at.into(),
            superseded_by,
        };
        advisory.validate()?;
        Ok(advisory)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("advisory.advisory_id", &self.advisory_id)?;
        self.coordinate.validate()?;
        ensure_digest("advisory.artifact_digest", &self.artifact_digest)?;
        ensure_text("advisory.severity", &self.severity)?;
        ensure_text("advisory.reason", &self.reason)?;
        ensure_text("advisory.published_at", &self.published_at)?;
        if let Some(coordinate) = &self.superseded_by {
            coordinate.validate()?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"advisory_id\":\"{}\",\"coordinate\":\"{}\",\"artifact_digest\":\"{}\",\"severity\":\"{}\",\"reason\":\"{}\",\"published_at\":\"{}\",\"superseded_by\":{}}}",
            REVOCATION_ADVISORY_SCHEMA_VERSION,
            escape_json(&self.advisory_id),
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.artifact_digest),
            escape_json(&self.severity),
            escape_json(&self.reason),
            escape_json(&self.published_at),
            self.superseded_by
                .as_ref()
                .map(|coordinate| format!("\"{}\"", escape_json(&coordinate.as_string())))
                .unwrap_or_else(|| "null".to_string())
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySnapshotV1 {
    pub snapshot_id: String,
    pub channel: ArtifactChannel,
    pub generated_at: String,
    pub expires_at: String,
    pub local_pinned: bool,
    pub registry_uri: Option<String>,
    pub snapshot_digest: String,
    pub entries: Vec<RegistryArtifactEntry>,
    pub advisories: Vec<RevocationAdvisoryV1>,
}

impl RegistrySnapshotV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_id: impl Into<String>,
        channel: ArtifactChannel,
        generated_at: impl Into<String>,
        expires_at: impl Into<String>,
        local_pinned: bool,
        registry_uri: Option<impl Into<String>>,
        snapshot_digest: impl Into<String>,
        entries: Vec<RegistryArtifactEntry>,
        advisories: Vec<RevocationAdvisoryV1>,
    ) -> Result<Self, EcosystemContractError> {
        let snapshot = Self {
            snapshot_id: snapshot_id.into(),
            channel,
            generated_at: generated_at.into(),
            expires_at: expires_at.into(),
            local_pinned,
            registry_uri: registry_uri.map(Into::into),
            snapshot_digest: snapshot_digest.into(),
            entries,
            advisories,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("snapshot.snapshot_id", &self.snapshot_id)?;
        ensure_text("snapshot.generated_at", &self.generated_at)?;
        ensure_text("snapshot.expires_at", &self.expires_at)?;
        ensure_digest("snapshot.snapshot_digest", &self.snapshot_digest)?;
        if !self.local_pinned && self.registry_uri.as_deref().unwrap_or("").is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "snapshot.registry_uri",
                reason: "non-pinned registry snapshots must record their registry URI".to_string(),
            });
        }
        if let Some(registry_uri) = &self.registry_uri {
            ensure_text("snapshot.registry_uri", registry_uri)?;
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        for advisory in &self.advisories {
            advisory.validate()?;
        }
        Ok(())
    }

    pub fn validate_at(&self, now: &str) -> Result<(), EcosystemContractError> {
        self.validate()?;
        ensure_text("snapshot.now", now)?;
        if self.expires_at <= now.to_string() {
            return Err(EcosystemContractError::Invalid {
                field: "snapshot.expires_at",
                reason: "expired registry snapshots must not be silently accepted".to_string(),
            });
        }
        Ok(())
    }

    pub fn stable_fingerprint(&self) -> String {
        stable_contract_hash(&self.to_json())
    }

    pub fn to_json(&self) -> String {
        let mut entries = self
            .entries
            .iter()
            .map(RegistryArtifactEntry::to_json)
            .collect::<Vec<_>>();
        entries.sort();
        let mut advisories = self
            .advisories
            .iter()
            .map(RevocationAdvisoryV1::to_json)
            .collect::<Vec<_>>();
        advisories.sort();
        format!(
            "{{\"schema\":\"{}\",\"snapshot_id\":\"{}\",\"channel\":\"{}\",\"generated_at\":\"{}\",\"expires_at\":\"{}\",\"local_pinned\":{},\"registry_uri\":{},\"snapshot_digest\":\"{}\",\"entries\":[{}],\"advisories\":[{}]}}",
            REGISTRY_SNAPSHOT_SCHEMA_VERSION,
            escape_json(&self.snapshot_id),
            self.channel.as_str(),
            escape_json(&self.generated_at),
            escape_json(&self.expires_at),
            self.local_pinned,
            optional_string_json(self.registry_uri.as_deref()),
            escape_json(&self.snapshot_digest),
            entries.join(","),
            advisories.join(",")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedArtifact {
    pub coordinate: ArtifactCoordinate,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub source_uri: Option<String>,
    pub trust_tier: TrustTier,
    pub dependencies: Vec<ArtifactCoordinate>,
}

impl ResolvedArtifact {
    pub fn new(
        coordinate: ArtifactCoordinate,
        manifest_digest: impl Into<String>,
        artifact_digest: impl Into<String>,
        source_uri: Option<impl Into<String>>,
        trust_tier: TrustTier,
        dependencies: Vec<ArtifactCoordinate>,
    ) -> Result<Self, EcosystemContractError> {
        let artifact = Self {
            coordinate,
            manifest_digest: manifest_digest.into(),
            artifact_digest: artifact_digest.into(),
            source_uri: source_uri.map(Into::into),
            trust_tier,
            dependencies,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        ensure_digest("resolved.manifest_digest", &self.manifest_digest)?;
        ensure_digest("resolved.artifact_digest", &self.artifact_digest)?;
        if let Some(source_uri) = &self.source_uri {
            ensure_text("resolved.source_uri", source_uri)?;
        }
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut dependencies = self
            .dependencies
            .iter()
            .map(ArtifactCoordinate::as_string)
            .collect::<Vec<_>>();
        dependencies.sort();
        format!(
            "{{\"coordinate\":\"{}\",\"manifest_digest\":\"{}\",\"artifact_digest\":\"{}\",\"source_uri\":{},\"trust_tier\":\"{}\",\"dependencies\":{}}}",
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.manifest_digest),
            escape_json(&self.artifact_digest),
            optional_string_json(self.source_uri.as_deref()),
            self.trust_tier.as_str(),
            string_array_json(&dependencies)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcosystemLockV1 {
    pub lock_id: String,
    pub registry_snapshot_digest: String,
    pub generated_at: String,
    pub generated_by: String,
    pub resolved_artifacts: Vec<ResolvedArtifact>,
}

impl EcosystemLockV1 {
    pub fn new(
        lock_id: impl Into<String>,
        registry_snapshot_digest: impl Into<String>,
        generated_at: impl Into<String>,
        generated_by: impl Into<String>,
        resolved_artifacts: Vec<ResolvedArtifact>,
    ) -> Result<Self, EcosystemContractError> {
        let lock = Self {
            lock_id: lock_id.into(),
            registry_snapshot_digest: registry_snapshot_digest.into(),
            generated_at: generated_at.into(),
            generated_by: generated_by.into(),
            resolved_artifacts,
        };
        lock.validate()?;
        Ok(lock)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("lock.lock_id", &self.lock_id)?;
        ensure_digest(
            "lock.registry_snapshot_digest",
            &self.registry_snapshot_digest,
        )?;
        ensure_text("lock.generated_at", &self.generated_at)?;
        ensure_text("lock.generated_by", &self.generated_by)?;
        if self.resolved_artifacts.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "lock.resolved_artifacts",
                reason: "lockfile must pin at least one resolved artifact".to_string(),
            });
        }
        for artifact in &self.resolved_artifacts {
            artifact.validate()?;
        }
        Ok(())
    }

    pub fn stable_hash(&self) -> String {
        stable_contract_hash(&self.to_json())
    }

    pub fn to_json(&self) -> String {
        let mut artifacts = self
            .resolved_artifacts
            .iter()
            .map(ResolvedArtifact::to_json)
            .collect::<Vec<_>>();
        artifacts.sort();
        format!(
            "{{\"schema\":\"{}\",\"lock_id\":\"{}\",\"registry_snapshot_digest\":\"{}\",\"generated_at\":\"{}\",\"generated_by\":\"{}\",\"resolved_artifacts\":[{}]}}",
            ECOSYSTEM_LOCK_SCHEMA_VERSION,
            escape_json(&self.lock_id),
            escape_json(&self.registry_snapshot_digest),
            escape_json(&self.generated_at),
            escape_json(&self.generated_by),
            artifacts.join(",")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactVerificationReportV1 {
    pub report_id: String,
    pub coordinate: ArtifactCoordinate,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub digest_match: bool,
    pub signature_verified: bool,
    pub sbom_verified: bool,
    pub revoked: bool,
    pub unknown_required_fields_rejected: bool,
    pub trust_tier: TrustTier,
    pub production_promotable: bool,
    pub failure: Option<String>,
}

impl ArtifactVerificationReportV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        report_id: impl Into<String>,
        coordinate: ArtifactCoordinate,
        manifest_digest: impl Into<String>,
        artifact_digest: impl Into<String>,
        digest_match: bool,
        signature_verified: bool,
        sbom_verified: bool,
        revoked: bool,
        unknown_required_fields_rejected: bool,
        trust_tier: TrustTier,
        production_promotable: bool,
        failure: Option<impl Into<String>>,
    ) -> Result<Self, EcosystemContractError> {
        let report = Self {
            report_id: report_id.into(),
            coordinate,
            manifest_digest: manifest_digest.into(),
            artifact_digest: artifact_digest.into(),
            digest_match,
            signature_verified,
            sbom_verified,
            revoked,
            unknown_required_fields_rejected,
            trust_tier,
            production_promotable,
            failure: failure.map(Into::into),
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("verification.report_id", &self.report_id)?;
        self.coordinate.validate()?;
        ensure_digest("verification.manifest_digest", &self.manifest_digest)?;
        ensure_digest("verification.artifact_digest", &self.artifact_digest)?;
        if self.production_promotable && !self.trust_tier.production_eligible() {
            return Err(EcosystemContractError::Invalid {
                field: "verification.production_promotable",
                reason: "community and local-dev artifacts cannot be production-promotable"
                    .to_string(),
            });
        }
        if let Some(failure) = &self.failure {
            ensure_text("verification.failure", failure)?;
        }
        Ok(())
    }

    pub fn accepted_for_production(&self) -> bool {
        self.digest_match
            && self.signature_verified
            && self.sbom_verified
            && !self.revoked
            && self.unknown_required_fields_rejected
            && self.production_promotable
            && self.trust_tier.production_eligible()
            && self.failure.is_none()
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"report_id\":\"{}\",\"coordinate\":\"{}\",\"manifest_digest\":\"{}\",\"artifact_digest\":\"{}\",\"digest_match\":{},\"signature_verified\":{},\"sbom_verified\":{},\"revoked\":{},\"unknown_required_fields_rejected\":{},\"trust_tier\":\"{}\",\"production_promotable\":{},\"accepted_for_production\":{},\"failure\":{}}}",
            ARTIFACT_VERIFICATION_REPORT_SCHEMA_VERSION,
            escape_json(&self.report_id),
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.manifest_digest),
            escape_json(&self.artifact_digest),
            self.digest_match,
            self.signature_verified,
            self.sbom_verified,
            self.revoked,
            self.unknown_required_fields_rejected,
            self.trust_tier.as_str(),
            self.production_promotable,
            self.accepted_for_production(),
            optional_string_json(self.failure.as_deref())
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactStagingReportV1 {
    pub staging_id: String,
    pub coordinate: ArtifactCoordinate,
    pub staged_path: String,
    pub manifest_digest: String,
    pub staged_artifact_digest: String,
    pub verification_report_digest: String,
    pub inert: bool,
    pub activation_prepared: bool,
}

impl ArtifactStagingReportV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        staging_id: impl Into<String>,
        coordinate: ArtifactCoordinate,
        staged_path: impl Into<String>,
        manifest_digest: impl Into<String>,
        staged_artifact_digest: impl Into<String>,
        verification_report_digest: impl Into<String>,
        inert: bool,
        activation_prepared: bool,
    ) -> Result<Self, EcosystemContractError> {
        let report = Self {
            staging_id: staging_id.into(),
            coordinate,
            staged_path: staged_path.into(),
            manifest_digest: manifest_digest.into(),
            staged_artifact_digest: staged_artifact_digest.into(),
            verification_report_digest: verification_report_digest.into(),
            inert,
            activation_prepared,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("staging.staging_id", &self.staging_id)?;
        self.coordinate.validate()?;
        ensure_text("staging.staged_path", &self.staged_path)?;
        ensure_digest("staging.manifest_digest", &self.manifest_digest)?;
        ensure_digest(
            "staging.staged_artifact_digest",
            &self.staged_artifact_digest,
        )?;
        ensure_digest(
            "staging.verification_report_digest",
            &self.verification_report_digest,
        )?;
        if !self.inert {
            return Err(EcosystemContractError::Invalid {
                field: "staging.inert",
                reason: "staged artifacts must be explicitly inert".to_string(),
            });
        }
        if self.activation_prepared {
            return Err(EcosystemContractError::Invalid {
                field: "staging.activation_prepared",
                reason: "staging must not prepare activation side effects".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema\":\"{}\",\"staging_id\":\"{}\",\"coordinate\":\"{}\",\"staged_path\":\"{}\",\"manifest_digest\":\"{}\",\"staged_artifact_digest\":\"{}\",\"verification_report_digest\":\"{}\",\"inert\":{},\"activation_prepared\":{}}}",
            ARTIFACT_STAGING_REPORT_SCHEMA_VERSION,
            escape_json(&self.staging_id),
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.staged_path),
            escape_json(&self.manifest_digest),
            escape_json(&self.staged_artifact_digest),
            escape_json(&self.verification_report_digest),
            self.inert,
            self.activation_prepared
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationReportV1 {
    pub activation_id: String,
    pub activated_artifacts: Vec<ArtifactCoordinate>,
    pub agent_core_plan_id: String,
    pub security_execution_run_id: String,
    pub audit_event_range: String,
    pub approval_id: String,
    pub approval_token_hash: String,
    pub policy_version: String,
    pub rollback_handle: String,
    pub activation_diff_hash: String,
    pub previous_active_set_hash: String,
}

impl ActivationReportV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activation_id: impl Into<String>,
        activated_artifacts: Vec<ArtifactCoordinate>,
        agent_core_plan_id: impl Into<String>,
        security_execution_run_id: impl Into<String>,
        audit_event_range: impl Into<String>,
        approval_id: impl Into<String>,
        approval_token_hash: impl Into<String>,
        policy_version: impl Into<String>,
        rollback_handle: impl Into<String>,
        activation_diff_hash: impl Into<String>,
        previous_active_set_hash: impl Into<String>,
    ) -> Result<Self, EcosystemContractError> {
        let report = Self {
            activation_id: activation_id.into(),
            activated_artifacts,
            agent_core_plan_id: agent_core_plan_id.into(),
            security_execution_run_id: security_execution_run_id.into(),
            audit_event_range: audit_event_range.into(),
            approval_id: approval_id.into(),
            approval_token_hash: approval_token_hash.into(),
            policy_version: policy_version.into(),
            rollback_handle: rollback_handle.into(),
            activation_diff_hash: activation_diff_hash.into(),
            previous_active_set_hash: previous_active_set_hash.into(),
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("activation_report.activation_id", &self.activation_id)?;
        ensure_text(
            "activation_report.agent_core_plan_id",
            &self.agent_core_plan_id,
        )?;
        ensure_text(
            "activation_report.security_execution_run_id",
            &self.security_execution_run_id,
        )?;
        ensure_text(
            "activation_report.audit_event_range",
            &self.audit_event_range,
        )?;
        ensure_text("activation_report.approval_id", &self.approval_id)?;
        ensure_digest(
            "activation_report.approval_token_hash",
            &self.approval_token_hash,
        )?;
        ensure_text("activation_report.policy_version", &self.policy_version)?;
        ensure_text("activation_report.rollback_handle", &self.rollback_handle)?;
        ensure_digest(
            "activation_report.activation_diff_hash",
            &self.activation_diff_hash,
        )?;
        ensure_digest(
            "activation_report.previous_active_set_hash",
            &self.previous_active_set_hash,
        )?;
        if self.activated_artifacts.is_empty() {
            return Err(EcosystemContractError::Invalid {
                field: "activation_report.activated_artifacts",
                reason: "activation report must list activated artifacts".to_string(),
            });
        }
        for coordinate in &self.activated_artifacts {
            coordinate.validate()?;
            if !coordinate.kind.alpha_activatable() {
                return Err(EcosystemContractError::Invalid {
                    field: "activation_report.activated_artifacts",
                    reason: "unsupported artifact kind cannot activate in alpha".to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn stable_fingerprint(&self) -> String {
        stable_contract_hash(&self.to_json())
    }

    pub fn to_json(&self) -> String {
        let mut artifacts = self
            .activated_artifacts
            .iter()
            .map(ArtifactCoordinate::as_string)
            .collect::<Vec<_>>();
        artifacts.sort();
        format!(
            "{{\"schema\":\"{}\",\"activation_id\":\"{}\",\"activated_artifacts\":{},\"agent_core_plan_id\":\"{}\",\"security_execution_run_id\":\"{}\",\"audit_event_range\":\"{}\",\"approval_id\":\"{}\",\"approval_token_hash\":\"{}\",\"policy_version\":\"{}\",\"rollback_handle\":\"{}\",\"activation_diff_hash\":\"{}\",\"previous_active_set_hash\":\"{}\"}}",
            ACTIVATION_REPORT_SCHEMA_VERSION,
            escape_json(&self.activation_id),
            string_array_json(&artifacts),
            escape_json(&self.agent_core_plan_id),
            escape_json(&self.security_execution_run_id),
            escape_json(&self.audit_event_range),
            escape_json(&self.approval_id),
            escape_json(&self.approval_token_hash),
            escape_json(&self.policy_version),
            escape_json(&self.rollback_handle),
            escape_json(&self.activation_diff_hash),
            escape_json(&self.previous_active_set_hash)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveArtifactState {
    pub coordinate: ArtifactCoordinate,
    pub manifest_digest: String,
    pub activation_report_id: String,
    pub rollback_handle: String,
    pub policy_version: String,
}

impl ActiveArtifactState {
    pub fn new(
        coordinate: ArtifactCoordinate,
        manifest_digest: impl Into<String>,
        activation_report_id: impl Into<String>,
        rollback_handle: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Result<Self, EcosystemContractError> {
        let state = Self {
            coordinate,
            manifest_digest: manifest_digest.into(),
            activation_report_id: activation_report_id.into(),
            rollback_handle: rollback_handle.into(),
            policy_version: policy_version.into(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        ensure_digest("active.manifest_digest", &self.manifest_digest)?;
        ensure_text("active.activation_report_id", &self.activation_report_id)?;
        ensure_text("active.rollback_handle", &self.rollback_handle)?;
        ensure_text("active.policy_version", &self.policy_version)?;
        Ok(())
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"coordinate\":\"{}\",\"manifest_digest\":\"{}\",\"activation_report_id\":\"{}\",\"rollback_handle\":\"{}\",\"policy_version\":\"{}\"}}",
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.manifest_digest),
            escape_json(&self.activation_report_id),
            escape_json(&self.rollback_handle),
            escape_json(&self.policy_version)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveArtifactSetV1 {
    pub set_id: String,
    pub artifacts: Vec<ActiveArtifactState>,
    pub lock_hash: String,
    pub activation_report_id: String,
    pub audit_event_range: String,
    pub generated_at: String,
}

impl ActiveArtifactSetV1 {
    pub fn new(
        set_id: impl Into<String>,
        artifacts: Vec<ActiveArtifactState>,
        lock_hash: impl Into<String>,
        activation_report_id: impl Into<String>,
        audit_event_range: impl Into<String>,
        generated_at: impl Into<String>,
    ) -> Result<Self, EcosystemContractError> {
        let active_set = Self {
            set_id: set_id.into(),
            artifacts,
            lock_hash: lock_hash.into(),
            activation_report_id: activation_report_id.into(),
            audit_event_range: audit_event_range.into(),
            generated_at: generated_at.into(),
        };
        active_set.validate()?;
        Ok(active_set)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("active_set.set_id", &self.set_id)?;
        ensure_digest("active_set.lock_hash", &self.lock_hash)?;
        ensure_text(
            "active_set.activation_report_id",
            &self.activation_report_id,
        )?;
        ensure_text("active_set.audit_event_range", &self.audit_event_range)?;
        ensure_text("active_set.generated_at", &self.generated_at)?;
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        Ok(())
    }

    pub fn state_hash(&self) -> String {
        stable_contract_hash(&self.to_json())
    }

    pub fn revocation_projection(
        &self,
        snapshot: &RegistrySnapshotV1,
    ) -> Result<ActiveArtifactRevocationProjectionV1, EcosystemContractError> {
        self.validate()?;
        snapshot.validate()?;
        let artifacts = self
            .artifacts
            .iter()
            .map(|active| ActiveArtifactRevocationStatus::from_active(active, snapshot))
            .collect::<Result<Vec<_>, _>>()?;
        ActiveArtifactRevocationProjectionV1::new(
            format!("revocation-{}", self.set_id),
            self.set_id.clone(),
            snapshot.snapshot_id.clone(),
            snapshot.snapshot_digest.clone(),
            artifacts,
        )
    }

    pub fn to_json(&self) -> String {
        let mut artifacts = self
            .artifacts
            .iter()
            .map(ActiveArtifactState::to_json)
            .collect::<Vec<_>>();
        artifacts.sort();
        format!(
            "{{\"schema\":\"{}\",\"set_id\":\"{}\",\"artifacts\":[{}],\"lock_hash\":\"{}\",\"activation_report_id\":\"{}\",\"audit_event_range\":\"{}\",\"generated_at\":\"{}\"}}",
            ACTIVE_ARTIFACT_SET_SCHEMA_VERSION,
            escape_json(&self.set_id),
            artifacts.join(","),
            escape_json(&self.lock_hash),
            escape_json(&self.activation_report_id),
            escape_json(&self.audit_event_range),
            escape_json(&self.generated_at)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveArtifactRevocationStatus {
    pub coordinate: ArtifactCoordinate,
    pub manifest_digest: String,
    pub artifact_digest: Option<String>,
    pub revoked: bool,
    pub degraded: bool,
    pub advisory_ids: Vec<String>,
    pub reason: String,
}

impl ActiveArtifactRevocationStatus {
    pub fn from_active(
        active: &ActiveArtifactState,
        snapshot: &RegistrySnapshotV1,
    ) -> Result<Self, EcosystemContractError> {
        active.validate()?;
        snapshot.validate()?;
        let entry = snapshot.entries.iter().find(|entry| {
            entry.coordinate == active.coordinate && entry.manifest_digest == active.manifest_digest
        });
        let artifact_digest = entry.map(|entry| entry.artifact_digest.clone());
        let mut advisory_ids = Vec::new();
        if let Some(entry) = entry {
            advisory_ids.extend(entry.advisory_refs.iter().cloned());
            advisory_ids.extend(
                snapshot
                    .advisories
                    .iter()
                    .filter(|advisory| {
                        advisory.coordinate == active.coordinate
                            && advisory.artifact_digest == entry.artifact_digest
                    })
                    .map(|advisory| advisory.advisory_id.clone()),
            );
        }
        advisory_ids.sort();
        advisory_ids.dedup();
        let revoked = entry.map(|entry| entry.revoked).unwrap_or(false);
        let degraded = entry.is_none() || revoked || !advisory_ids.is_empty();
        let reason = if entry.is_none() {
            "active artifact missing from registry snapshot"
        } else if revoked {
            "active artifact is revoked"
        } else if !advisory_ids.is_empty() {
            "active artifact has advisory metadata"
        } else {
            "ok"
        }
        .to_string();
        let status = Self {
            coordinate: active.coordinate.clone(),
            manifest_digest: active.manifest_digest.clone(),
            artifact_digest,
            revoked,
            degraded,
            advisory_ids,
            reason,
        };
        status.validate()?;
        Ok(status)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        ensure_digest("active_revocation.manifest_digest", &self.manifest_digest)?;
        if let Some(digest) = &self.artifact_digest {
            ensure_digest("active_revocation.artifact_digest", digest)?;
        }
        for advisory_id in &self.advisory_ids {
            ensure_text("active_revocation.advisory_id", advisory_id)?;
        }
        ensure_text("active_revocation.reason", &self.reason)?;
        Ok(())
    }

    pub fn to_json(&self) -> String {
        let mut advisory_ids = self.advisory_ids.clone();
        advisory_ids.sort();
        format!(
            "{{\"coordinate\":\"{}\",\"manifest_digest\":\"{}\",\"artifact_digest\":{},\"revoked\":{},\"degraded\":{},\"advisory_ids\":{},\"reason\":\"{}\"}}",
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.manifest_digest),
            optional_string_json(self.artifact_digest.as_deref()),
            self.revoked,
            self.degraded,
            string_array_json(&advisory_ids),
            escape_json(&self.reason)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveArtifactRevocationProjectionV1 {
    pub projection_id: String,
    pub active_set_id: String,
    pub registry_snapshot_id: String,
    pub registry_snapshot_digest: String,
    pub artifacts: Vec<ActiveArtifactRevocationStatus>,
}

impl ActiveArtifactRevocationProjectionV1 {
    pub fn new(
        projection_id: impl Into<String>,
        active_set_id: impl Into<String>,
        registry_snapshot_id: impl Into<String>,
        registry_snapshot_digest: impl Into<String>,
        artifacts: Vec<ActiveArtifactRevocationStatus>,
    ) -> Result<Self, EcosystemContractError> {
        let projection = Self {
            projection_id: projection_id.into(),
            active_set_id: active_set_id.into(),
            registry_snapshot_id: registry_snapshot_id.into(),
            registry_snapshot_digest: registry_snapshot_digest.into(),
            artifacts,
        };
        projection.validate()?;
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("active_revocation.projection_id", &self.projection_id)?;
        ensure_text("active_revocation.active_set_id", &self.active_set_id)?;
        ensure_text(
            "active_revocation.registry_snapshot_id",
            &self.registry_snapshot_id,
        )?;
        ensure_digest(
            "active_revocation.registry_snapshot_digest",
            &self.registry_snapshot_digest,
        )?;
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        Ok(())
    }

    pub fn degraded_count(&self) -> usize {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.degraded)
            .count()
    }

    pub fn to_json(&self) -> String {
        let mut artifacts = self
            .artifacts
            .iter()
            .map(ActiveArtifactRevocationStatus::to_json)
            .collect::<Vec<_>>();
        artifacts.sort();
        format!(
            "{{\"schema\":\"{}\",\"projection_id\":\"{}\",\"active_set_id\":\"{}\",\"registry_snapshot_id\":\"{}\",\"registry_snapshot_digest\":\"{}\",\"degraded_count\":{},\"artifacts\":[{}]}}",
            ACTIVE_ARTIFACT_REVOCATION_PROJECTION_SCHEMA_VERSION,
            escape_json(&self.projection_id),
            escape_json(&self.active_set_id),
            escape_json(&self.registry_snapshot_id),
            escape_json(&self.registry_snapshot_digest),
            self.degraded_count(),
            artifacts.join(",")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeactivationReportV1 {
    pub deactivation_id: String,
    pub coordinate: ArtifactCoordinate,
    pub agent_core_plan_id: String,
    pub security_execution_run_id: String,
    pub audit_event_range: String,
    pub rollback_handle: String,
    pub policy_version: String,
}

impl DeactivationReportV1 {
    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("deactivation.deactivation_id", &self.deactivation_id)?;
        self.coordinate.validate()?;
        ensure_text("deactivation.agent_core_plan_id", &self.agent_core_plan_id)?;
        ensure_text(
            "deactivation.security_execution_run_id",
            &self.security_execution_run_id,
        )?;
        ensure_text("deactivation.audit_event_range", &self.audit_event_range)?;
        ensure_text("deactivation.rollback_handle", &self.rollback_handle)?;
        ensure_text("deactivation.policy_version", &self.policy_version)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackReportV1 {
    pub rollback_id: String,
    pub rollback_handle: String,
    pub restored_active_set_hash: String,
    pub audit_event_range: String,
    pub success: bool,
}

impl RollbackReportV1 {
    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        ensure_text("rollback.rollback_id", &self.rollback_id)?;
        ensure_text("rollback.rollback_handle", &self.rollback_handle)?;
        ensure_digest(
            "rollback.restored_active_set_hash",
            &self.restored_active_set_hash,
        )?;
        ensure_text("rollback.audit_event_range", &self.audit_event_range)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityValidationReportV1 {
    pub coordinate: ArtifactCoordinate,
    pub runtime_contract_version: String,
    pub architecture: String,
    pub supported_runtime: bool,
    pub supported_architecture: bool,
    pub missing_required_features: Vec<String>,
    pub missing_optional_features: Vec<String>,
    pub downgrade_requested: bool,
    pub rollback_contract: Option<String>,
    pub can_activate: bool,
}

impl CompatibilityValidationReportV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinate: ArtifactCoordinate,
        runtime_contract_version: impl Into<String>,
        architecture: impl Into<String>,
        supported_runtime: bool,
        supported_architecture: bool,
        missing_required_features: Vec<String>,
        missing_optional_features: Vec<String>,
        downgrade_requested: bool,
        rollback_contract: Option<String>,
        can_activate: bool,
    ) -> Result<Self, EcosystemContractError> {
        let report = Self {
            coordinate,
            runtime_contract_version: runtime_contract_version.into(),
            architecture: architecture.into(),
            supported_runtime,
            supported_architecture,
            missing_required_features,
            missing_optional_features,
            downgrade_requested,
            rollback_contract,
            can_activate,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<(), EcosystemContractError> {
        self.coordinate.validate()?;
        ensure_semver(
            "compatibility_report.runtime_contract_version",
            &self.runtime_contract_version,
        )?;
        ensure_text("compatibility_report.architecture", &self.architecture)?;
        if self.downgrade_requested && self.rollback_contract.as_deref().unwrap_or("").is_empty() {
            if self.can_activate {
                return Err(EcosystemContractError::Invalid {
                    field: "compatibility_report.can_activate",
                    reason: "downgrade cannot activate without rollback contract".to_string(),
                });
            }
        }
        for value in self
            .missing_required_features
            .iter()
            .chain(self.missing_optional_features.iter())
        {
            ensure_text("compatibility_report.feature", value)?;
        }
        if let Some(rollback_contract) = &self.rollback_contract {
            ensure_text("compatibility_report.rollback_contract", rollback_contract)?;
        }
        Ok(())
    }

    pub fn blocks_activation(&self) -> bool {
        !self.can_activate
    }

    pub fn to_json(&self) -> String {
        let mut missing_required = self.missing_required_features.clone();
        missing_required.sort();
        let mut missing_optional = self.missing_optional_features.clone();
        missing_optional.sort();
        format!(
            "{{\"schema\":\"{}\",\"coordinate\":\"{}\",\"runtime_contract_version\":\"{}\",\"architecture\":\"{}\",\"supported_runtime\":{},\"supported_architecture\":{},\"missing_required_features\":{},\"missing_optional_features\":{},\"downgrade_requested\":{},\"rollback_contract\":{},\"can_activate\":{}}}",
            COMPATIBILITY_REPORT_SCHEMA_VERSION,
            escape_json(&self.coordinate.as_string()),
            escape_json(&self.runtime_contract_version),
            escape_json(&self.architecture),
            self.supported_runtime,
            self.supported_architecture,
            string_array_json(&missing_required),
            string_array_json(&missing_optional),
            self.downgrade_requested,
            optional_string_json(self.rollback_contract.as_deref()),
            self.can_activate
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcosystemContractError {
    Invalid { field: &'static str, reason: String },
    SecretValue { field: &'static str },
}

impl EcosystemContractError {
    pub fn reason(&self) -> String {
        match self {
            Self::Invalid { reason, .. } => reason.clone(),
            Self::SecretValue { field } => {
                format!("secret-like value is not allowed in {field}")
            }
        }
    }
}

impl std::fmt::Display for EcosystemContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason())
    }
}

impl std::error::Error for EcosystemContractError {}

pub fn stable_contract_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let hex: String = Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:agentos-stable-v1-{hex}")
}

fn runtime_in_range(runtime: &str, min: &str, max: &str) -> bool {
    matches!(
        (compare_semver(runtime, min), compare_semver(runtime, max),),
        (
            Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater),
            Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Less)
        )
    )
}

fn compare_semver(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    let left = semver_core(left)?;
    let right = semver_core(right)?;
    Some(left.cmp(&right))
}

fn semver_core(value: &str) -> Option<(u64, u64, u64)> {
    let core = value.split_once('-').map(|(core, _)| core).unwrap_or(value);
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

fn ensure_semver(field: &'static str, value: &str) -> Result<(), EcosystemContractError> {
    ensure_text(field, value)?;
    if !is_semver_like(value) {
        return Err(EcosystemContractError::Invalid {
            field,
            reason: "value must be semver-like".to_string(),
        });
    }
    Ok(())
}

fn is_semver_like(value: &str) -> bool {
    semver_core(value).is_some()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '+'))
}

fn missing_values(required: &[String], actual: &[String]) -> Vec<String> {
    let mut missing = required
        .iter()
        .filter(|value| !actual.iter().any(|actual| actual == *value))
        .cloned()
        .collect::<Vec<_>>();
    missing.sort();
    missing
}

fn ensure_identifier_segment(
    field: &'static str,
    value: &str,
) -> Result<(), EcosystemContractError> {
    ensure_text(field, value)?;
    if !value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(EcosystemContractError::Invalid {
            field,
            reason: "identity segment must be lowercase ASCII with - _ . separators".to_string(),
        });
    }
    Ok(())
}

fn ensure_secret_handle(field: &'static str, value: &str) -> Result<(), EcosystemContractError> {
    ensure_text(field, value)?;
    if !value.starts_with("secret://")
        || value.len() <= "secret://".len()
        || value.chars().any(char::is_whitespace)
    {
        return Err(EcosystemContractError::Invalid {
            field,
            reason: "credential references must be single-token secret:// handles".to_string(),
        });
    }
    Ok(())
}

fn ensure_semantic_tool_name(
    field: &'static str,
    value: &str,
) -> Result<(), EcosystemContractError> {
    ensure_text(field, value)?;
    if is_shell_surface(value)
        || !value.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
        })
    {
        return Err(EcosystemContractError::Invalid {
            field,
            reason: "tool names must be semantic lowercase identifiers, not shell surfaces"
                .to_string(),
        });
    }
    Ok(())
}

fn is_shell_surface(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "sh" | "bash" | "cmd" | "cmd.exe" | "powershell" | "pwsh" | "shell" | "exec"
    ) || lower.contains("shell")
        || lower.contains("exec.")
        || lower.ends_with(".exec")
}

fn ensure_text(field: &'static str, value: &str) -> Result<(), EcosystemContractError> {
    if value.trim().is_empty() {
        return Err(EcosystemContractError::Invalid {
            field,
            reason: "value must not be empty".to_string(),
        });
    }
    if contains_secret_value(value) {
        return Err(EcosystemContractError::SecretValue { field });
    }
    Ok(())
}

fn ensure_digest(field: &'static str, value: &str) -> Result<(), EcosystemContractError> {
    ensure_text(field, value)?;
    if !value.starts_with("sha256:") || value.len() <= "sha256:".len() {
        return Err(EcosystemContractError::Invalid {
            field,
            reason: "digest must be sha256-bound".to_string(),
        });
    }
    Ok(())
}

fn ensure_relative_artifact_path(
    field: &'static str,
    value: &str,
) -> Result<(), EcosystemContractError> {
    ensure_text(field, value)?;
    if value.starts_with('/') || value.contains('\\') || value.contains("..") {
        return Err(EcosystemContractError::Invalid {
            field,
            reason: "artifact file paths must be inert relative paths".to_string(),
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
mod manifest {
    use super::*;

    fn coordinate() -> ArtifactCoordinate {
        ArtifactCoordinate::parse("agentos:policy-pack/agentos/core-policy@1.0.0")
            .expect("coordinate")
    }

    fn compatibility() -> CompatibilityRequirement {
        CompatibilityRequirement::new(
            "0.1.0",
            "0.9.0",
            vec!["x86_64"],
            vec!["audit-journal"],
            vec!["kvm"],
            vec![],
        )
        .expect("compatibility")
    }

    fn trust(tier: TrustTier, production_promotable: bool) -> ArtifactTrust {
        ArtifactTrust::new(
            tier,
            Some("agentos-release"),
            Some("sha256:provenance"),
            Some("sha256:sbom"),
            Some("sha256:release"),
            production_promotable,
        )
        .expect("trust")
    }

    #[test]
    fn coordinate_round_trip_is_strict_and_deterministic() {
        let parsed = ArtifactCoordinate::parse("agentos:workflow-pack/agentos/setup@1.2.3")
            .expect("coordinate");
        assert_eq!(parsed.kind, ArtifactKind::WorkflowPack);
        assert_eq!(
            parsed.as_string(),
            "agentos:workflow-pack/agentos/setup@1.2.3"
        );
        assert!(ArtifactCoordinate::parse("agentos:unknown/agentos/setup@1.2.3").is_err());
        assert!(ArtifactCoordinate::parse("agentos:workflow-pack/agentos/setup@latest").is_err());
    }

    #[test]
    fn manifest_binds_digest_activation_and_unknown_required_fields() {
        let manifest = AgentOsArtifactManifestV1::new(
            coordinate(),
            "sha256:artifact",
            "0.1.0",
            compatibility(),
            vec![],
            vec![ArtifactFile::new("policy/core.json", "sha256:file", 42, false).unwrap()],
            ActivationRequirement::production_default("policy.v1").unwrap(),
            trust(TrustTier::Core, true),
            "scripts/functional-capability-replay.ps1 --ecosystem policy",
            Vec::<String>::new(),
        )
        .expect("manifest");

        assert!(
            manifest
                .to_json()
                .contains(ECOSYSTEM_MANIFEST_SCHEMA_VERSION)
        );
        assert!(
            manifest
                .to_json()
                .contains("\"requires_agent_core_plan_spec\":true")
        );
        assert!(manifest.validate_for_alpha_activation().is_ok());

        let error = AgentOsArtifactManifestV1::new(
            coordinate(),
            "sha1:not-accepted",
            "0.1.0",
            compatibility(),
            vec![],
            vec![ArtifactFile::new("policy/core.json", "sha256:file", 42, false).unwrap()],
            ActivationRequirement::production_default("policy.v1").unwrap(),
            trust(TrustTier::Core, true),
            "replay",
            Vec::<String>::new(),
        )
        .expect_err("digest fails closed");
        assert!(error.reason().contains("sha256"));

        let unknown = AgentOsArtifactManifestV1::new(
            coordinate(),
            "sha256:artifact",
            "0.1.0",
            compatibility(),
            vec![],
            vec![ArtifactFile::new("policy/core.json", "sha256:file", 42, false).unwrap()],
            ActivationRequirement::production_default("policy.v1").unwrap(),
            trust(TrustTier::Core, true),
            "replay",
            vec!["future-required-field"],
        )
        .expect_err("unknown required field rejected");
        assert!(unknown.reason().contains("unknown required fields"));
    }

    #[test]
    fn policy_pack_cannot_disable_core_activation_invariants() {
        let error = ActivationRequirement::new(
            true,
            true,
            true,
            "policy.v1",
            ["audit", "rollback"],
            ["audit-journal"],
        )
        .expect_err("core invariants must remain");
        assert!(error.reason().contains("no-shell"));

        let error = ActivationRequirement::new(
            true,
            false,
            true,
            "policy.v1",
            REQUIRED_CORE_INVARIANTS,
            ["audit-journal"],
        )
        .expect_err("security engine required");
        assert!(error.reason().contains("SecurityExecutionEngine"));
    }
}

#[cfg(test)]
mod registry {
    use super::*;

    fn coord(name: &str) -> ArtifactCoordinate {
        ArtifactCoordinate::new(ArtifactKind::WorkflowPack, "agentos", name, "1.0.0")
            .expect("coordinate")
    }

    fn trust() -> ArtifactTrust {
        ArtifactTrust::new(
            TrustTier::Verified,
            Some("agentos-release"),
            Some("sha256:provenance"),
            Some("sha256:sbom"),
            None::<String>,
            true,
        )
        .expect("trust")
    }

    fn entry(name: &str) -> RegistryArtifactEntry {
        RegistryArtifactEntry::new(
            coord(name),
            format!("sha256:manifest-{name}"),
            format!("sha256:artifact-{name}"),
            trust(),
            ArtifactChannel::Stable,
            None::<String>,
            false,
            Vec::<String>::new(),
        )
        .expect("entry")
    }

    #[test]
    fn local_pinned_snapshot_needs_no_live_registry_uri_but_expiry_is_enforced() {
        let snapshot = RegistrySnapshotV1::new(
            "snap-1",
            ArtifactChannel::Stable,
            "2026-05-24T00:00:00Z",
            "2026-06-01T00:00:00Z",
            true,
            None::<String>,
            "sha256:snapshot",
            vec![entry("setup")],
            vec![
                RevocationAdvisoryV1::new(
                    "ADV-1",
                    coord("old"),
                    "sha256:artifact-old",
                    "high",
                    "revoked by publisher",
                    "2026-05-24T00:00:00Z",
                    Some(coord("setup")),
                )
                .unwrap(),
            ],
        )
        .expect("snapshot");

        assert!(snapshot.validate_at("2026-05-25T00:00:00Z").is_ok());
        assert!(snapshot.validate_at("2026-06-02T00:00:00Z").is_err());
        assert!(snapshot.to_json().contains("\"registry_uri\":null"));
        assert!(
            snapshot
                .to_json()
                .contains(REVOCATION_ADVISORY_SCHEMA_VERSION)
        );
    }

    #[test]
    fn lockfile_hash_is_deterministic_and_binds_publisher_and_digest() {
        let left = ResolvedArtifact::new(
            coord("a"),
            "sha256:manifest-a",
            "sha256:artifact-a",
            None::<String>,
            TrustTier::Verified,
            vec![],
        )
        .unwrap();
        let right = ResolvedArtifact::new(
            coord("b"),
            "sha256:manifest-b",
            "sha256:artifact-b",
            None::<String>,
            TrustTier::Verified,
            vec![coord("a")],
        )
        .unwrap();

        let first = EcosystemLockV1::new(
            "lock-1",
            "sha256:snapshot",
            "2026-05-24T00:00:00Z",
            "aom",
            vec![left.clone(), right.clone()],
        )
        .unwrap();
        let second = EcosystemLockV1::new(
            "lock-1",
            "sha256:snapshot",
            "2026-05-24T00:00:00Z",
            "aom",
            vec![right, left],
        )
        .unwrap();

        assert_eq!(first.stable_hash(), second.stable_hash());
        assert!(
            first
                .to_json()
                .contains("agentos:workflow-pack/agentos/a@1.0.0")
        );
        assert!(first.to_json().contains("sha256:artifact-b"));
    }
}

#[cfg(test)]
mod revocation {
    use super::*;

    fn coord() -> ArtifactCoordinate {
        ArtifactCoordinate::new(ArtifactKind::PolicyPack, "agentos", "core-policy", "1.0.0")
            .expect("coordinate")
    }

    fn trust() -> ArtifactTrust {
        ArtifactTrust::new(
            TrustTier::Core,
            Some("agentos-release"),
            Some("sha256:provenance"),
            Some("sha256:sbom"),
            Some("sha256:release"),
            true,
        )
        .expect("trust")
    }

    fn entry(
        revoked: bool,
        artifact_digest: &str,
        advisory_refs: Vec<&str>,
    ) -> RegistryArtifactEntry {
        RegistryArtifactEntry::new(
            coord(),
            "sha256:manifest-core-policy",
            artifact_digest,
            trust(),
            ArtifactChannel::Stable,
            None::<String>,
            revoked,
            advisory_refs,
        )
        .expect("entry")
    }

    fn active_set() -> ActiveArtifactSetV1 {
        ActiveArtifactSetV1::new(
            "active-1",
            vec![
                ActiveArtifactState::new(
                    coord(),
                    "sha256:manifest-core-policy",
                    "act-1",
                    "rollback://active-set/0",
                    "policy.v1",
                )
                .expect("state"),
            ],
            "sha256:lock",
            "act-1",
            "audit:10..20",
            "2026-05-25T00:00:00Z",
        )
        .expect("active set")
    }

    #[test]
    fn active_revoked_artifact_is_flagged_degraded() {
        let snapshot = RegistrySnapshotV1::new(
            "snap-revoked",
            ArtifactChannel::Stable,
            "2026-05-25T00:00:00Z",
            "2026-06-01T00:00:00Z",
            true,
            None::<String>,
            "sha256:snapshot",
            vec![entry(
                true,
                "sha256:artifact-core-policy",
                vec!["ADV-CORE-1"],
            )],
            vec![
                RevocationAdvisoryV1::new(
                    "ADV-CORE-1",
                    coord(),
                    "sha256:artifact-core-policy",
                    "critical",
                    "publisher revoked this policy pack",
                    "2026-05-25T00:00:00Z",
                    None,
                )
                .unwrap(),
            ],
        )
        .expect("snapshot");

        let projection = active_set()
            .revocation_projection(&snapshot)
            .expect("projection");

        assert_eq!(projection.degraded_count(), 1);
        assert!(projection.artifacts[0].revoked);
        assert!(projection.artifacts[0].degraded);
        assert_eq!(projection.artifacts[0].advisory_ids, vec!["ADV-CORE-1"]);
        assert!(
            projection
                .to_json()
                .contains(ACTIVE_ARTIFACT_REVOCATION_PROJECTION_SCHEMA_VERSION)
        );
    }

    #[test]
    fn advisory_metadata_is_bound_to_artifact_digest() {
        let snapshot = RegistrySnapshotV1::new(
            "snap-digest-bound",
            ArtifactChannel::Stable,
            "2026-05-25T00:00:00Z",
            "2026-06-01T00:00:00Z",
            true,
            None::<String>,
            "sha256:snapshot",
            vec![entry(false, "sha256:artifact-current", Vec::new())],
            vec![
                RevocationAdvisoryV1::new(
                    "ADV-OLD",
                    coord(),
                    "sha256:artifact-old",
                    "high",
                    "old digest was revoked",
                    "2026-05-24T00:00:00Z",
                    None,
                )
                .unwrap(),
            ],
        )
        .expect("snapshot");

        let projection = active_set()
            .revocation_projection(&snapshot)
            .expect("projection");

        assert_eq!(projection.degraded_count(), 0);
        assert!(!projection.artifacts[0].degraded);
        assert!(projection.artifacts[0].advisory_ids.is_empty());
    }

    #[test]
    fn advisory_requires_digest_binding() {
        let error = RevocationAdvisoryV1::new(
            "ADV-BAD",
            coord(),
            "not-a-digest",
            "critical",
            "bad advisory",
            "2026-05-25T00:00:00Z",
            None,
        )
        .expect_err("advisory must bind digest");

        assert!(error.reason().contains("sha256"));
    }
}

#[cfg(test)]
mod activation {
    use super::*;

    fn coord() -> ArtifactCoordinate {
        ArtifactCoordinate::new(ArtifactKind::PolicyPack, "agentos", "core-policy", "1.0.0")
            .unwrap()
    }

    #[test]
    fn staging_state_is_explicitly_inert() {
        let report = ArtifactStagingReportV1::new(
            "stage-1",
            coord(),
            "/var/lib/agentos/ecosystem/staged/core-policy",
            "sha256:manifest",
            "sha256:artifact",
            "sha256:verification",
            true,
            false,
        )
        .expect("staging");
        assert!(report.to_json().contains("\"inert\":true"));

        let error = ArtifactStagingReportV1::new(
            "stage-1",
            coord(),
            "/var/lib/agentos/ecosystem/staged/core-policy",
            "sha256:manifest",
            "sha256:artifact",
            "sha256:verification",
            false,
            false,
        )
        .expect_err("staged state must be inert");
        assert!(error.reason().contains("inert"));
    }

    #[test]
    fn activation_report_binds_plan_security_audit_approval_and_rollback() {
        let report = ActivationReportV1::new(
            "act-1",
            vec![coord()],
            "plan-1",
            "sec-run-1",
            "audit:10..20",
            "approval-1",
            "sha256:approval-token",
            "policy.v1",
            "rollback://active-set/0",
            "sha256:activation-diff",
            "sha256:previous-active-set",
        )
        .expect("activation report");

        assert!(
            report
                .to_json()
                .contains("\"agent_core_plan_id\":\"plan-1\"")
        );
        assert!(
            report
                .to_json()
                .contains("\"security_execution_run_id\":\"sec-run-1\"")
        );
        assert!(
            report
                .to_json()
                .contains("\"rollback_handle\":\"rollback://active-set/0\"")
        );

        let error = ActivationReportV1::new(
            "act-1",
            vec![
                ArtifactCoordinate::new(
                    ArtifactKind::RuntimeAdapterPack,
                    "agentos",
                    "adapter",
                    "1.0.0",
                )
                .unwrap(),
            ],
            "plan-1",
            "sec-run-1",
            "audit:10..20",
            "approval-1",
            "sha256:approval-token",
            "policy.v1",
            "rollback://active-set/0",
            "sha256:activation-diff",
            "sha256:previous-active-set",
        )
        .expect_err("unsupported kind cannot activate");
        assert!(error.reason().contains("unsupported artifact kind"));
    }

    #[test]
    fn active_set_is_reconstructable_after_restart() {
        let state = ActiveArtifactState::new(
            coord(),
            "sha256:manifest",
            "act-1",
            "rollback://active-set/0",
            "policy.v1",
        )
        .expect("state");
        let active_set = ActiveArtifactSetV1::new(
            "active-1",
            vec![state],
            "sha256:lock",
            "act-1",
            "audit:10..20",
            "2026-05-24T00:00:00Z",
        )
        .expect("active set");
        assert!(
            active_set
                .to_json()
                .contains(ACTIVE_ARTIFACT_SET_SCHEMA_VERSION)
        );
        assert!(
            active_set
                .state_hash()
                .starts_with("sha256:agentos-stable-v1-")
        );
    }
}

#[cfg(test)]
mod compatibility {
    use super::*;

    fn coord() -> ArtifactCoordinate {
        ArtifactCoordinate::new(ArtifactKind::WorkflowPack, "agentos", "setup", "1.0.0").unwrap()
    }

    #[test]
    fn incompatible_runtime_blocks_activation() {
        let requirement = CompatibilityRequirement::new(
            "0.2.0",
            "0.3.0",
            vec!["x86_64"],
            vec!["audit-journal"],
            Vec::<String>::new(),
            Vec::<MigrationRule>::new(),
        )
        .unwrap();
        let report = requirement
            .evaluate(
                coord(),
                "0.1.0",
                "x86_64",
                vec!["audit-journal"],
                false,
                None::<String>,
            )
            .unwrap();
        assert!(report.blocks_activation());
        assert!(!report.supported_runtime);
    }

    #[test]
    fn optional_dependencies_degrade_without_host_mutation() {
        let dependency = ArtifactDependency::optional_read_only(
            ArtifactCoordinate::new(ArtifactKind::ExecutionImagePack, "agentos", "fc", "1.0.0")
                .unwrap(),
        )
        .expect("optional dep");
        assert_eq!(
            dependency.missing_behavior,
            DependencyMissingBehavior::DegradeReadOnly
        );

        let error = ArtifactDependency::new(
            dependency.coordinate,
            true,
            DependencyMissingBehavior::DegradeReadOnly,
            true,
        )
        .expect_err("host mutation denied");
        assert!(error.reason().contains("host mutation"));
    }

    #[test]
    fn downgrade_requires_explicit_rollback_contract() {
        let error =
            MigrationRule::new("2.0.0", "1.0.0", None::<String>).expect_err("rollback needed");
        assert!(error.reason().contains("rollback"));

        let requirement = CompatibilityRequirement::new(
            "0.1.0",
            "0.9.0",
            vec!["x86_64"],
            Vec::<String>::new(),
            vec!["kvm"],
            vec![MigrationRule::new("2.0.0", "1.0.0", Some("rollback://artifact/setup")).unwrap()],
        )
        .unwrap();
        let report = requirement
            .evaluate(
                coord(),
                "0.1.0",
                "x86_64",
                Vec::<String>::new(),
                true,
                Some("rollback://artifact/setup"),
            )
            .unwrap();
        assert!(!report.blocks_activation());
        assert_eq!(report.missing_optional_features, vec!["kvm"]);
    }
}

#[cfg(test)]
mod ecosystem_packs {
    use super::*;

    fn coord(kind: ArtifactKind, name: &str) -> ArtifactCoordinate {
        ArtifactCoordinate::new(kind, "agentos", name, "1.0.0").expect("coordinate")
    }

    fn compatibility() -> CompatibilityRequirement {
        CompatibilityRequirement::new(
            "0.1.0",
            "0.9.0",
            vec!["x86_64"],
            vec!["audit-journal"],
            vec!["kvm", "firecracker"],
            vec![
                MigrationRule::new("2.0.0", "1.0.0", Some("rollback://image/agentos-sandbox"))
                    .unwrap(),
            ],
        )
        .expect("compatibility")
    }

    #[test]
    fn model_profile_pack_keeps_baseline_local_and_routes_through_broker() {
        let local_profile = ModelEndpointProfile::new(
            "baseline-local",
            ModelProviderMode::Local,
            "agentos-local-stub",
            vec![ModelRuntimeRole::Plan, ModelRuntimeRole::Summarize],
            None::<String>,
            vec!["secret://model/local-routing"],
            false,
            true,
        )
        .expect("local profile");
        let remote_profile = ModelEndpointProfile::new(
            "optional-remote",
            ModelProviderMode::RemoteOptional,
            "operator-approved-remote",
            vec![ModelRuntimeRole::Classify, ModelRuntimeRole::Sanitize],
            Some("policy:model-remote-egress"),
            vec!["secret://model/remote-api"],
            false,
            true,
        )
        .expect("remote profile");

        let pack = ModelProfilePackV1::new(
            coord(ArtifactKind::ModelProfilePack, "model-routing"),
            vec![remote_profile, local_profile],
            vec![ModelProviderMode::Stub, ModelProviderMode::Local],
            true,
            true,
            true,
        )
        .expect("model pack");

        assert!(pack.to_json().contains(MODEL_PROFILE_PACK_SCHEMA_VERSION));
        assert!(pack.to_json().contains("\"broker_required\":true"));

        let direct = ModelEndpointProfile::new(
            "direct-provider",
            ModelProviderMode::Local,
            "direct-provider",
            vec![ModelRuntimeRole::Plan],
            None::<String>,
            Vec::<String>::new(),
            true,
            true,
        )
        .expect_err("direct provider bypass rejected");
        assert!(direct.reason().contains("ModelBroker"));

        let raw_secret = ModelEndpointProfile::new(
            "raw-secret",
            ModelProviderMode::RemoteOptional,
            "remote",
            vec![ModelRuntimeRole::Summarize],
            Some("policy:model-remote-egress"),
            vec!["token=abc123"],
            false,
            true,
        )
        .expect_err("raw credential rejected");
        assert!(raw_secret.reason().contains("secret"));

        let missing_gate = ModelEndpointProfile::new(
            "missing-gate",
            ModelProviderMode::RemoteOptional,
            "remote",
            vec![ModelRuntimeRole::Summarize],
            None::<String>,
            Vec::<String>::new(),
            false,
            true,
        )
        .expect_err("remote provider must be gated");
        assert!(missing_gate.reason().contains("policy-gated"));
    }

    #[test]
    fn knowledge_pack_quarantines_untrusted_context_and_blocks_authority_claims() {
        let source = KnowledgeSourceV1::new(
            "vendor-guide",
            "local://knowledge/vendor-guide.md",
            "sha256:knowledge-vendor-guide",
            KnowledgeTrustLabel::Untrusted,
            86_400,
            MemoryScope::Quarantined,
            true,
            4096,
        )
        .expect("knowledge source");
        let pack = KnowledgePackV1::new(
            coord(ArtifactKind::KnowledgePack, "vendor-guide"),
            vec![source],
            true,
            true,
            false,
            false,
        )
        .expect("knowledge pack");

        assert!(pack.to_json().contains(KNOWLEDGE_PACK_SCHEMA_VERSION));
        assert!(pack.to_json().contains("\"trust_label\":\"untrusted\""));

        let unquarantined = KnowledgeSourceV1::new(
            "unsafe",
            "local://knowledge/unsafe.md",
            "sha256:knowledge-unsafe",
            KnowledgeTrustLabel::Suspicious,
            60,
            MemoryScope::PlannerContext,
            false,
            1024,
        )
        .expect_err("suspicious knowledge must quarantine");
        assert!(unquarantined.reason().contains("quarantined"));

        let approval_claim = KnowledgePackV1::new(
            coord(ArtifactKind::KnowledgePack, "approval-claim"),
            vec![
                KnowledgeSourceV1::new(
                    "claim",
                    "local://knowledge/claim.md",
                    "sha256:knowledge-claim",
                    KnowledgeTrustLabel::OrganizationCurated,
                    60,
                    MemoryScope::PlannerContext,
                    false,
                    1024,
                )
                .unwrap(),
            ],
            true,
            true,
            true,
            false,
        )
        .expect_err("knowledge cannot create approvals");
        assert!(approval_claim.reason().contains("approval claims"));
    }

    #[test]
    fn runtime_adapter_pack_requires_semantic_tools_and_security_execution() {
        let binding = RuntimeAdapterToolBinding::new(
            "service.restart",
            RiskClass::PrivilegedWithHumanApproval,
            "policy:service-restart",
            vec!["systemd"],
            vec!["cgroup-v2"],
            DependencyMissingBehavior::DegradeReadOnly,
        )
        .expect("binding");
        let pack = RuntimeAdapterPackV1::new(
            coord(ArtifactKind::RuntimeAdapterPack, "service-adapter"),
            vec![binding],
            true,
            false,
            true,
        )
        .expect("adapter pack");

        assert!(pack.to_json().contains(RUNTIME_ADAPTER_PACK_SCHEMA_VERSION));
        assert!(
            pack.to_json()
                .contains("\"risk_class\":\"privileged-with-human-approval\"")
        );

        let shell = RuntimeAdapterToolBinding::new(
            "shell.exec",
            RiskClass::ExecuteWithConfirmation,
            "policy:shell",
            Vec::<String>::new(),
            Vec::<String>::new(),
            DependencyMissingBehavior::DegradeReadOnly,
        )
        .expect_err("shell surface denied");
        assert!(shell.reason().contains("shell"));

        let direct_host = RuntimeAdapterPackV1::new(
            coord(ArtifactKind::RuntimeAdapterPack, "direct-host"),
            vec![
                RuntimeAdapterToolBinding::new(
                    "service.restart",
                    RiskClass::PrivilegedWithHumanApproval,
                    "policy:service-restart",
                    Vec::<String>::new(),
                    Vec::<String>::new(),
                    DependencyMissingBehavior::DegradeReadOnly,
                )
                .unwrap(),
            ],
            true,
            true,
            true,
        )
        .expect_err("direct host mutation denied");
        assert!(direct_host.reason().contains("directly"));
    }

    #[test]
    fn execution_image_pack_pins_images_and_denies_host_fallback() {
        let firecracker = ArtifactDependency::optional_read_only(coord(
            ArtifactKind::RuntimeAdapterPack,
            "firecracker-executor",
        ))
        .expect("firecracker dependency");
        let pack = ExecutionImagePackV1::new(
            coord(ArtifactKind::ExecutionImagePack, "agentos-sandbox"),
            "sha256:kernel",
            "sha256:rootfs",
            "sha256:image",
            "sha256:provenance",
            compatibility(),
            firecracker.clone(),
            true,
            false,
            true,
            "rollback://image/agentos-sandbox/previous",
        )
        .expect("image pack");

        assert!(pack.to_json().contains(EXECUTION_IMAGE_PACK_SCHEMA_VERSION));
        assert!(pack.to_json().contains("\"host_fallback_allowed\":false"));
        assert!(
            pack.to_json()
                .contains("\"active_artifact_set_hash_required\":true")
        );

        let host_fallback = ExecutionImagePackV1::new(
            coord(ArtifactKind::ExecutionImagePack, "host-fallback"),
            "sha256:kernel",
            "sha256:rootfs",
            "sha256:image",
            "sha256:provenance",
            compatibility(),
            firecracker.clone(),
            true,
            true,
            true,
            "rollback://image/host-fallback/previous",
        )
        .expect_err("host fallback denied");
        assert!(host_fallback.reason().contains("host execution"));

        let no_active_set = ExecutionImagePackV1::new(
            coord(ArtifactKind::ExecutionImagePack, "missing-active-set"),
            "sha256:kernel",
            "sha256:rootfs",
            "sha256:image",
            "sha256:provenance",
            compatibility(),
            firecracker,
            true,
            false,
            false,
            "rollback://image/missing-active-set/previous",
        )
        .expect_err("active set binding required");
        assert!(no_active_set.reason().contains("active artifact set"));
    }
}
