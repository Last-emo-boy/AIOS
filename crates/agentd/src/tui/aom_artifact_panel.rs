use std::fs;
use std::path::{Path, PathBuf};

use crate::agent_core::ecosystem::{LocalArtifactRecord, LocalRegistrySnapshot};
use crate::aom::{DEFAULT_LOCAL_REGISTRY_PATH, DEFAULT_STAGING_ROOT};
use crate::api::escape_json;
use crate::audit::redact_summary;
use crate::operator_projection::DEFAULT_ACTIVE_ARTIFACT_SET_PATH;
use crate::runtime_contracts::ArtifactCoordinate;

pub const AOM_ARTIFACT_PANEL_SCHEMA_VERSION: &str = "agentos.tui-aom-artifact-panel.v1";

const RUNTIME_CONTRACT_VERSION: &str = "0.1.0";
const RUNTIME_ARCHITECTURE: &str = "x86_64";
const HOST_FEATURES: &[&str] = &["audit-journal", "rollback-store"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AomArtifactPanel {
    pub schema_version: &'static str,
    pub coordinate: String,
    pub kind: String,
    pub publisher: String,
    pub name: String,
    pub version: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub trust_tier: String,
    pub production_eligible: bool,
    pub source_uri: String,
    pub registry_path: String,
    pub registry_snapshot_digest: String,
    pub lifecycle_state: String,
    pub staged: bool,
    pub active: bool,
    pub blocked: bool,
    pub revoked: bool,
    pub incompatible: bool,
    pub degraded: bool,
    pub compatibility_status: String,
    pub missing_required_features: Vec<String>,
    pub missing_optional_features: Vec<String>,
    pub activation_prepared: bool,
    pub staging_report_path: String,
    pub verification_report_path: String,
    pub active_set_path: String,
    pub signature_verified: Option<bool>,
    pub sbom_verified: Option<bool>,
    pub accepted_for_production: Option<bool>,
    pub production_promotable: Option<bool>,
    pub advisory_refs: Vec<String>,
    pub dependencies: Vec<String>,
}

impl AomArtifactPanel {
    pub fn collect(coordinate: &str) -> Result<Self, String> {
        Self::collect_from_paths(
            coordinate,
            resolve_repo_path(DEFAULT_LOCAL_REGISTRY_PATH),
            resolve_repo_path(DEFAULT_STAGING_ROOT),
            resolve_repo_path(DEFAULT_ACTIVE_ARTIFACT_SET_PATH),
        )
    }

    pub fn collect_from_paths(
        coordinate: &str,
        registry_path: impl AsRef<Path>,
        staging_root: impl AsRef<Path>,
        active_set_path: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let coordinate = ArtifactCoordinate::parse(coordinate).map_err(|error| error.reason())?;
        let registry_path = registry_path.as_ref();
        let staging_root = staging_root.as_ref();
        let active_set_path = active_set_path.as_ref();
        let snapshot =
            LocalRegistrySnapshot::from_file(registry_path).map_err(|error| error.reason())?;
        let artifact = snapshot.artifact(&coordinate).ok_or_else(|| {
            format!(
                "artifact is missing from local registry: {}",
                coordinate.as_string()
            )
        })?;
        let staging = StagingEvidence::collect(staging_root, &coordinate.as_string());
        let active = ActiveSetEvidence::collect(active_set_path, &coordinate.as_string());
        let compatibility = CompatibilityProjection::from_artifact(artifact);
        let revoked = artifact.revoked || staging.verification_revoked.unwrap_or(false);
        let incompatible = compatibility.blocks_activation();
        let blocked = revoked || incompatible;
        let active = active.active;
        let staged = staging.staged;
        let activation_prepared = staging.activation_prepared.unwrap_or(false);
        let lifecycle_state = lifecycle_state(blocked, revoked, incompatible, active, staged);
        let dependencies = artifact
            .dependencies
            .iter()
            .map(ArtifactCoordinate::as_string)
            .collect::<Vec<_>>();
        Ok(Self {
            schema_version: AOM_ARTIFACT_PANEL_SCHEMA_VERSION,
            coordinate: coordinate.as_string(),
            kind: coordinate.kind.as_str().to_string(),
            publisher: coordinate.publisher,
            name: coordinate.name,
            version: coordinate.version,
            manifest_digest: artifact.manifest_digest.clone(),
            artifact_digest: artifact.artifact_digest.clone(),
            trust_tier: artifact.trust_tier.as_str().to_string(),
            production_eligible: artifact.trust_tier.production_eligible(),
            source_uri: artifact.source_uri.clone(),
            registry_path: registry_path.display().to_string(),
            registry_snapshot_digest: snapshot.snapshot_digest.clone(),
            lifecycle_state,
            staged,
            active,
            blocked,
            revoked,
            incompatible,
            degraded: active && blocked,
            compatibility_status: compatibility.status,
            missing_required_features: compatibility.missing_required_features,
            missing_optional_features: compatibility.missing_optional_features,
            activation_prepared,
            staging_report_path: staging
                .staging_report_path
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
            verification_report_path: staging
                .verification_report_path
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
            active_set_path: active_set_path.display().to_string(),
            signature_verified: staging.signature_verified,
            sbom_verified: staging.sbom_verified,
            accepted_for_production: staging.accepted_for_production,
            production_promotable: staging.production_promotable,
            advisory_refs: artifact.advisory_refs.clone(),
            dependencies,
        })
    }

    pub fn render(&self) -> String {
        [
            "TUI AOM Artifact".to_string(),
            format!(
                "aom_artifact_panel schema={} read_only=true projection_controller_only=true resolver_logic=false resolver_owner=agent_core::ecosystem direct_execute=false normal_shell_available=false coordinate=\"{}\"",
                self.schema_version,
                escape_json(&redact_summary(&self.coordinate))
            ),
            format!(
                "artifact_detail coordinate=\"{}\" kind={} publisher=\"{}\" name=\"{}\" version=\"{}\" manifest_digest=\"{}\" artifact_digest=\"{}\" trust_tier={} production_eligible={} source_uri=\"{}\"",
                escape_json(&redact_summary(&self.coordinate)),
                escape_json(&self.kind),
                escape_json(&self.publisher),
                escape_json(&self.name),
                escape_json(&self.version),
                escape_json(&self.manifest_digest),
                escape_json(&self.artifact_digest),
                escape_json(&self.trust_tier),
                self.production_eligible,
                escape_json(&redact_summary(&self.source_uri))
            ),
            format!(
                "artifact_state lifecycle_state={} staged={} active={} blocked={} revoked={} incompatible={} degraded={} staged_artifacts_active=false install_inert=true stage_inert=true activation_prepared={}",
                escape_json(&self.lifecycle_state),
                self.staged,
                self.active,
                self.blocked,
                self.revoked,
                self.incompatible,
                self.degraded,
                self.activation_prepared
            ),
            format!(
                "trust_status trust_tier={} production_eligible={} production_promotable={} signature_verified={} sbom_verified={} accepted_for_production={} advisory_refs=\"{}\" dependencies=\"{}\"",
                escape_json(&self.trust_tier),
                self.production_eligible,
                optional_bool(self.production_promotable),
                optional_bool(self.signature_verified),
                optional_bool(self.sbom_verified),
                optional_bool(self.accepted_for_production),
                escape_json(&redact_summary(&sorted_join(&self.advisory_refs))),
                escape_json(&redact_summary(&sorted_join(&self.dependencies)))
            ),
            format!(
                "compatibility_status status={} runtime_contract_version={} architecture={} missing_required_features=\"{}\" missing_optional_features=\"{}\" can_activate={}",
                escape_json(&self.compatibility_status),
                RUNTIME_CONTRACT_VERSION,
                RUNTIME_ARCHITECTURE,
                escape_json(&sorted_join(&self.missing_required_features)),
                escape_json(&sorted_join(&self.missing_optional_features)),
                !self.blocked
            ),
            format!(
                "activation_preview status={} activation_prepared=false security_execution_required=true agent_core_plan_spec_required=true approval_required=true rollback_required=true direct_activate=false launch_preview=\"aom.activate.preview {}\"",
                if self.blocked { "blocked" } else { "requires-runtime-mediation" },
                escape_json(&redact_summary(&self.coordinate))
            ),
            "aom_invariant install_stage_inert=true activation_requires_runtime_mediation=true authority_path=\"agent_core::ecosystem -> AgentCore PlanSpec -> SecurityExecutionEngine -> approval -> rollback\" agentd_resolver_logic=false trust_ui_authority=false".to_string(),
            format!(
                "evidence registry_path=\"{}\" registry_snapshot_digest=\"{}\" staging_report=\"{}\" verification_report=\"{}\" active_set_path=\"{}\"",
                escape_json(&redact_summary(&self.registry_path)),
                escape_json(&self.registry_snapshot_digest),
                escape_json(&redact_summary(&self.staging_report_path)),
                escape_json(&redact_summary(&self.verification_report_path)),
                escape_json(&redact_summary(&self.active_set_path))
            ),
        ]
        .join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagingEvidence {
    staged: bool,
    activation_prepared: Option<bool>,
    staging_report_path: Option<PathBuf>,
    verification_report_path: Option<PathBuf>,
    signature_verified: Option<bool>,
    sbom_verified: Option<bool>,
    accepted_for_production: Option<bool>,
    production_promotable: Option<bool>,
    verification_revoked: Option<bool>,
}

impl StagingEvidence {
    fn collect(root: &Path, coordinate: &str) -> Self {
        let Some(staging_report_path) = find_report(root, "staging-report.json", coordinate) else {
            return Self {
                staged: false,
                activation_prepared: None,
                staging_report_path: None,
                verification_report_path: None,
                signature_verified: None,
                sbom_verified: None,
                accepted_for_production: None,
                production_promotable: None,
                verification_revoked: None,
            };
        };
        let staging_content = fs::read_to_string(&staging_report_path).unwrap_or_default();
        let verification_report_path = staging_report_path
            .parent()
            .map(|parent| parent.join("verification-report.json"))
            .filter(|path| path.is_file());
        let verification_content = verification_report_path
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok())
            .unwrap_or_default();
        Self {
            staged: true,
            activation_prepared: json_bool(&staging_content, "activation_prepared"),
            staging_report_path: Some(staging_report_path),
            verification_report_path,
            signature_verified: json_bool(&verification_content, "signature_verified"),
            sbom_verified: json_bool(&verification_content, "sbom_verified"),
            accepted_for_production: json_bool(&verification_content, "accepted_for_production"),
            production_promotable: json_bool(&verification_content, "production_promotable"),
            verification_revoked: json_bool(&verification_content, "revoked"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSetEvidence {
    active: bool,
}

impl ActiveSetEvidence {
    fn collect(path: &Path, coordinate: &str) -> Self {
        let active = fs::read_to_string(path)
            .ok()
            .map(|content| {
                json_string_values(&content, "coordinate").contains(&coordinate.to_string())
            })
            .unwrap_or(false);
        Self { active }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompatibilityProjection {
    status: String,
    missing_required_features: Vec<String>,
    missing_optional_features: Vec<String>,
}

impl CompatibilityProjection {
    fn from_artifact(artifact: &LocalArtifactRecord) -> Self {
        let runtime_supported = version_in_range(
            RUNTIME_CONTRACT_VERSION,
            &artifact.min_runtime_contract_version,
            &artifact.max_runtime_contract_version,
        );
        let architecture_supported = artifact
            .architectures
            .iter()
            .any(|architecture| architecture == RUNTIME_ARCHITECTURE);
        let missing_required_features = missing_features(&artifact.required_host_features);
        let missing_optional_features = missing_features(&artifact.optional_host_features);
        let status = if runtime_supported
            && architecture_supported
            && missing_required_features.is_empty()
        {
            "compatible"
        } else {
            "incompatible"
        }
        .to_string();
        Self {
            status,
            missing_required_features,
            missing_optional_features,
        }
    }

    fn blocks_activation(&self) -> bool {
        self.status != "compatible"
    }
}

fn lifecycle_state(
    blocked: bool,
    revoked: bool,
    incompatible: bool,
    active: bool,
    staged: bool,
) -> String {
    if blocked && revoked {
        "blocked-revoked"
    } else if blocked && incompatible {
        "blocked-incompatible"
    } else if active {
        "active"
    } else if staged {
        "staged-inert"
    } else {
        "registry-only"
    }
    .to_string()
}

fn missing_features(features: &[String]) -> Vec<String> {
    let mut missing = features
        .iter()
        .filter(|feature| !HOST_FEATURES.contains(&feature.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    missing.sort();
    missing
}

fn version_in_range(version: &str, minimum: &str, maximum: &str) -> bool {
    let Some(version) = parse_version(version) else {
        return false;
    };
    let Some(minimum) = parse_version(minimum) else {
        return false;
    };
    let Some(maximum) = parse_version(maximum) else {
        return false;
    };
    version >= minimum && version <= maximum
}

fn parse_version(value: &str) -> Option<Vec<u64>> {
    let parts = value
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.is_empty() { None } else { Some(parts) }
}

fn find_report(root: &Path, filename: &str, coordinate: &str) -> Option<PathBuf> {
    let mut matches = Vec::new();
    collect_reports(root, filename, coordinate, &mut matches);
    matches.sort();
    matches.into_iter().next()
}

fn collect_reports(root: &Path, filename: &str, coordinate: &str, matches: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_reports(&path, filename, coordinate, matches);
        } else if path.file_name().and_then(|name| name.to_str()) == Some(filename) {
            let contains_coordinate = fs::read_to_string(&path)
                .ok()
                .map(|content| {
                    json_string_values(&content, "coordinate").contains(&coordinate.to_string())
                })
                .unwrap_or(false);
            if contains_coordinate {
                matches.push(path);
            }
        }
    }
}

fn json_bool(content: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let start = content.find(&needle)? + needle.len();
    let colon_relative = content[start..].find(':')?;
    let value = content[start + colon_relative + 1..].trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn json_string_values(content: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let mut values = Vec::new();
    let mut offset = 0;
    while let Some(relative_start) = content[offset..].find(&needle) {
        let start = offset + relative_start + needle.len();
        let Some(colon_relative) = content[start..].find(':') else {
            break;
        };
        let mut value_start = start + colon_relative + 1;
        while content
            .as_bytes()
            .get(value_start)
            .is_some_and(u8::is_ascii_whitespace)
        {
            value_start += 1;
        }
        if content.as_bytes().get(value_start) != Some(&b'"') {
            offset = value_start;
            continue;
        }
        let rest = &content[value_start + 1..];
        let mut value = String::new();
        let mut escaped = false;
        for (index, ch) in rest.char_indices() {
            if escaped {
                value.push(ch);
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => {
                    values.push(value);
                    offset = value_start + index + 2;
                    break;
                }
                _ => value.push(ch),
            }
        }
        if offset <= value_start {
            break;
        }
    }
    values
}

fn optional_bool(value: Option<bool>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn sorted_join(values: &[String]) -> String {
    if values.is_empty() {
        return "-".to_string();
    }
    let mut values = values.to_vec();
    values.sort();
    values.join("|")
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
