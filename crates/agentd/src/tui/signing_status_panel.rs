use std::fs;
use std::path::{Path, PathBuf};

use crate::api::escape_json;
use crate::audit::redact_summary;
use crate::runtime_contracts::stable_contract_hash;

use super::release_provenance_panel::{
    DEFAULT_RELEASE_ARTIFACT_DIR, json_array_section, json_bool, json_object_section, json_string,
    json_string_array, resolve_repo_path,
};

pub const SIGNING_STATUS_PANEL_SCHEMA_VERSION: &str = "agentos.tui-signing-status-panel.v1";

const PROVENANCE_FILE: &str = "provenance.json";
const PRODUCTION_VERIFICATION_SCRIPT: &str = "scripts/verify-production-signatures.ps1";
const PRODUCTION_SIGNATURE_SCHEMA: &str = "agentos.production-detached-signature.v1";
const PRODUCTION_KEY_ID: &str = "agentos-production-root-v1";
const CANDIDATE_SIGNATURE_SCHEMA: &str = "agentos.release-detached-signature.v1";
const CANDIDATE_SIGNATURE_ALGORITHM: &str = "sha256-hash-bound-candidate-signature-v1";
const CANDIDATE_KEY_ID: &str = "agentos-candidate-release-hash-bound-v1";
const DEFAULT_SIGNATURE_NAMES: &[&str] = &[
    "dependency_inventory",
    "sbom",
    "update_metadata",
    "provenance",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningStatusPanel {
    pub schema_version: &'static str,
    pub release_dir: String,
    pub provenance_path: String,
    pub provenance_present: bool,
    pub signing_policy: SigningPolicyProjection,
    pub candidate_signatures: Vec<CandidateSignatureProjection>,
    pub production_signatures: Vec<ProductionSignatureProjection>,
    pub production_verification: ProductionVerificationProjection,
    pub blockers: Vec<SigningBlocker>,
}

impl SigningStatusPanel {
    pub fn collect() -> Self {
        Self::collect_from_dir(resolve_repo_path(DEFAULT_RELEASE_ARTIFACT_DIR))
    }

    pub fn collect_from_dir(release_dir: impl AsRef<Path>) -> Self {
        let release_dir = release_dir.as_ref().to_path_buf();
        let provenance_path = release_dir.join(PROVENANCE_FILE);
        let provenance_content = fs::read_to_string(&provenance_path).ok();
        let provenance_present = provenance_content.is_some();
        let signing_object = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "signing"))
            .unwrap_or_default();
        let artifacts_object = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "artifacts"))
            .unwrap_or_default();
        let signing_policy = SigningPolicyProjection::collect(&signing_object);
        let mut required_names = signing_policy.required_detached_signatures.clone();
        if required_names.is_empty() {
            required_names = DEFAULT_SIGNATURE_NAMES
                .iter()
                .map(ToString::to_string)
                .collect();
        }
        let candidate_signatures = required_names
            .iter()
            .map(|name| CandidateSignatureProjection::collect(&release_dir, name, &signing_policy))
            .collect::<Vec<_>>();
        let production_signatures = required_names
            .iter()
            .map(|name| {
                ProductionSignatureProjection::collect(&release_dir, &artifacts_object, name)
            })
            .collect::<Vec<_>>();
        let verification_path = production_verification_path(&release_dir);
        let production_verification = ProductionVerificationProjection::collect(&verification_path);
        let blockers = collect_blockers(
            provenance_present,
            &candidate_signatures,
            &production_signatures,
            &production_verification,
        );

        Self {
            schema_version: SIGNING_STATUS_PANEL_SCHEMA_VERSION,
            release_dir: release_dir.display().to_string(),
            provenance_path: provenance_path.display().to_string(),
            provenance_present,
            signing_policy,
            candidate_signatures,
            production_signatures,
            production_verification,
            blockers,
        }
    }

    pub fn render(&self) -> String {
        let candidate_present = self
            .candidate_signatures
            .iter()
            .filter(|signature| signature.status == "present")
            .count();
        let candidate_missing = self.candidate_signatures.len() - candidate_present;
        let production_present = self
            .production_signatures
            .iter()
            .filter(|signature| signature.present)
            .count();
        let production_missing = self.production_signatures.len() - production_present;
        let production_status =
            production_status(&self.production_verification, production_missing);
        let mut lines = vec![
            "TUI Signing Status".to_string(),
            format!(
                "signing_status_panel schema={} read_only=true projection_controller_only=true signing_authority=false production_signing_authority=false direct_sign=false direct_promote=false private_key_material_visible=false key_path_visible=false production_blocker_link=\"promotion.blockers.show\"",
                self.schema_version
            ),
            format!(
                "candidate_signing status={} scope=candidate-only total={} present={} missing={} production_ready_claim=false candidate_is_production_signature=false candidate_signature_satisfies_production=false",
                if candidate_missing == 0 { "candidate-present" } else { "candidate-blocked" },
                self.candidate_signatures.len(),
                candidate_present,
                candidate_missing
            ),
            format!(
                "signing_policy schema=\"{}\" algorithm=\"{}\" key_id=\"{}\" production_key_required={} fail_closed={} required_detached_signatures=\"{}\" provenance_present={} provenance_path=\"{}\"",
                safe_text(&self.signing_policy.signature_schema),
                safe_text(&self.signing_policy.algorithm),
                safe_text(&self.signing_policy.key_id),
                self.signing_policy.production_key_required,
                self.signing_policy.fail_closed,
                safe_join(&self.signing_policy.required_detached_signatures),
                self.provenance_present,
                safe_text(&self.provenance_path)
            ),
            format!(
                "production_signing status={} required_for_ga=true required_schema=\"{}\" required_key_id=\"{}\" production_ready=false production_ready_claim=false missing_production_signature={} production_signature_count={} required_signature_count={} verification_result_present={} verification_script=\"{}\"",
                production_status,
                PRODUCTION_SIGNATURE_SCHEMA,
                PRODUCTION_KEY_ID,
                production_missing > 0,
                production_present,
                self.production_signatures.len(),
                self.production_verification.present,
                PRODUCTION_VERIFICATION_SCRIPT
            ),
            format!(
                "production_signature_verification status={} present={} path=\"{}\" blocker_count={} decision_evidence_required={} verification_production_ready_claim={} tui_accepts_candidate_signature_as_production=false",
                safe_text(&self.production_verification.status),
                self.production_verification.present,
                safe_text(&self.production_verification.path),
                self.production_verification.blockers.len(),
                self.production_verification.decision_evidence_required,
                self.production_verification.production_ready_claim
            ),
            "signing_invariants candidate_signature_scope=candidate-only production_signature_scope=production-only signing_execution_in_tui=false verification_execution_in_tui=false release_artifact_mutation_in_tui=false production_promotion_in_tui=false key_material_projection=redacted hashes_paths_and_status_only=true".to_string(),
        ];
        lines.extend(
            self.candidate_signatures
                .iter()
                .map(CandidateSignatureProjection::render),
        );
        lines.extend(
            self.production_signatures
                .iter()
                .map(ProductionSignatureProjection::render),
        );
        if self.blockers.is_empty() {
            lines.push("signing_blocker id=none severity=none status=clear evidence_path=\"-\" safe_next_command=\"release.provenance.show\" message=\"candidate signatures are present and production signatures have verification evidence\"".to_string());
        } else {
            lines.extend(self.blockers.iter().map(SigningBlocker::render));
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPolicyProjection {
    pub signature_schema: String,
    pub algorithm: String,
    pub key_id: String,
    pub production_key_required: bool,
    pub fail_closed: bool,
    pub required_detached_signatures: Vec<String>,
}

impl SigningPolicyProjection {
    fn collect(signing_object: &str) -> Self {
        Self {
            signature_schema: json_string(signing_object, "signature_schema")
                .unwrap_or_else(|| CANDIDATE_SIGNATURE_SCHEMA.to_string()),
            algorithm: json_string(signing_object, "algorithm")
                .unwrap_or_else(|| CANDIDATE_SIGNATURE_ALGORITHM.to_string()),
            key_id: json_string(signing_object, "key_id")
                .unwrap_or_else(|| CANDIDATE_KEY_ID.to_string()),
            production_key_required: json_bool(signing_object, "production_key_required")
                .unwrap_or(false),
            fail_closed: json_bool(signing_object, "fail_closed").unwrap_or(true),
            required_detached_signatures: json_string_array(
                signing_object,
                "required_detached_signatures",
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSignatureProjection {
    pub name: String,
    pub path: String,
    pub status: String,
    pub present: bool,
    pub schema: String,
    pub schema_matches: bool,
    pub artifact_name: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub signature_value_hash: String,
    pub algorithm: String,
    pub algorithm_matches: bool,
    pub key_id: String,
    pub key_matches: bool,
    pub production_key_required: bool,
    pub detached: bool,
    pub fail_closed: bool,
}

impl CandidateSignatureProjection {
    fn collect(release_dir: &Path, name: &str, policy: &SigningPolicyProjection) -> Self {
        let path = release_dir.join(candidate_signature_file_for_name(name));
        let content = fs::read_to_string(&path).ok();
        let artifact = content
            .as_deref()
            .and_then(|content| json_object_section(content, "artifact"))
            .unwrap_or_default();
        let signature = content
            .as_deref()
            .and_then(|content| json_object_section(content, "signature"))
            .unwrap_or_default();
        let key = content
            .as_deref()
            .and_then(|content| json_object_section(content, "key"))
            .unwrap_or_default();
        let signature_policy = content
            .as_deref()
            .and_then(|content| json_object_section(content, "policy"))
            .unwrap_or_default();
        let present = content.is_some();
        let schema = content
            .as_deref()
            .and_then(|content| json_string(content, "schema"))
            .unwrap_or_else(|| "missing".to_string());
        let algorithm =
            json_string(&signature, "algorithm").unwrap_or_else(|| "missing".to_string());
        let key_id = json_string(&key, "key_id").unwrap_or_else(|| "missing".to_string());
        let production_key_required =
            json_bool(&key, "production_key_required").unwrap_or(policy.production_key_required);
        let signature_value = json_string(&signature, "value").unwrap_or_default();

        Self {
            name: name.to_string(),
            path: path.display().to_string(),
            status: if present { "present" } else { "missing" }.to_string(),
            present,
            schema_matches: schema == policy.signature_schema,
            schema,
            artifact_name: json_string(&artifact, "name").unwrap_or_else(|| name.to_string()),
            artifact_path: json_string(&artifact, "path")
                .unwrap_or_else(|| artifact_file_for_name(name).to_string()),
            artifact_sha256: json_string(&artifact, "sha256")
                .unwrap_or_else(|| "missing".to_string()),
            signature_value_hash: if signature_value.is_empty() {
                "missing".to_string()
            } else {
                stable_contract_hash(&signature_value)
            },
            algorithm_matches: algorithm == policy.algorithm,
            algorithm,
            key_matches: key_id == policy.key_id,
            key_id,
            production_key_required,
            detached: json_bool(&signature_policy, "detached").unwrap_or(true),
            fail_closed: json_bool(&signature_policy, "fail_closed").unwrap_or(policy.fail_closed),
        }
    }

    fn render(&self) -> String {
        format!(
            "candidate_signature name={} status={} present={} schema=\"{}\" schema_matches={} artifact_name=\"{}\" artifact_path=\"{}\" artifact_sha256=\"{}\" signature_value_hash=\"{}\" algorithm=\"{}\" algorithm_matches={} key_id=\"{}\" key_matches={} production_key_required={} detached={} fail_closed={} candidate_only=true production_signature=false",
            safe_text(&self.name),
            safe_text(&self.status),
            self.present,
            safe_text(&self.schema),
            self.schema_matches,
            safe_text(&self.artifact_name),
            safe_text(&self.artifact_path),
            safe_text(&self.artifact_sha256),
            safe_text(&self.signature_value_hash),
            safe_text(&self.algorithm),
            self.algorithm_matches,
            safe_text(&self.key_id),
            self.key_matches,
            self.production_key_required,
            self.detached,
            self.fail_closed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionSignatureProjection {
    pub name: String,
    pub artifact_path: String,
    pub path: String,
    pub status: String,
    pub present: bool,
    pub schema: String,
    pub algorithm: String,
    pub key_id: String,
}

impl ProductionSignatureProjection {
    fn collect(release_dir: &Path, artifacts_object: &str, name: &str) -> Self {
        let artifact_path = artifact_path_for_name(release_dir, artifacts_object, name);
        let production_path = PathBuf::from(format!("{}.prod.sig.json", artifact_path.display()));
        let content = fs::read_to_string(&production_path).ok();
        let signature = content
            .as_deref()
            .and_then(|content| json_object_section(content, "signature"))
            .unwrap_or_default();
        let key = content
            .as_deref()
            .and_then(|content| json_object_section(content, "key"))
            .unwrap_or_default();
        let present = content.is_some();
        Self {
            name: name.to_string(),
            artifact_path: artifact_path.display().to_string(),
            path: production_path.display().to_string(),
            status: if present { "present" } else { "missing" }.to_string(),
            present,
            schema: content
                .as_deref()
                .and_then(|content| json_string(content, "schema"))
                .unwrap_or_else(|| "missing".to_string()),
            algorithm: json_string(&signature, "algorithm")
                .unwrap_or_else(|| "missing".to_string()),
            key_id: json_string(&key, "key_id").unwrap_or_else(|| "missing".to_string()),
        }
    }

    fn render(&self) -> String {
        format!(
            "production_signature name={} status={} present={} required_for_ga=true candidate_signature_satisfies=false schema=\"{}\" expected_schema=\"{}\" artifact_path=\"{}\" path=\"{}\" algorithm=\"{}\" key_id=\"{}\" expected_key_id=\"{}\"",
            safe_text(&self.name),
            safe_text(&self.status),
            self.present,
            safe_text(&self.schema),
            PRODUCTION_SIGNATURE_SCHEMA,
            safe_text(&self.artifact_path),
            safe_text(&self.path),
            safe_text(&self.algorithm),
            safe_text(&self.key_id),
            PRODUCTION_KEY_ID
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionVerificationProjection {
    pub path: String,
    pub present: bool,
    pub status: String,
    pub production_ready_claim: bool,
    pub decision_evidence_required: bool,
    pub blockers: Vec<VerificationBlockerProjection>,
}

impl ProductionVerificationProjection {
    fn collect(path: &Path) -> Self {
        let content = fs::read_to_string(path).ok();
        let present = content.is_some();
        let blockers = content
            .as_deref()
            .and_then(|content| json_array_section(content, "blockers"))
            .map(|section| {
                json_objects_in_array(&section)
                    .into_iter()
                    .map(VerificationBlockerProjection::from_json)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Self {
            path: path.display().to_string(),
            present,
            status: content
                .as_deref()
                .and_then(|content| json_string(content, "status"))
                .unwrap_or_else(|| "missing".to_string()),
            production_ready_claim: content
                .as_deref()
                .and_then(|content| json_bool(content, "production_ready_claim"))
                .unwrap_or(false),
            decision_evidence_required: content
                .as_deref()
                .and_then(|content| json_bool(content, "decision_evidence_required"))
                .unwrap_or(false),
            blockers,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationBlockerProjection {
    pub id: String,
    pub status: String,
    pub severity: String,
    pub message: String,
}

impl VerificationBlockerProjection {
    fn from_json(content: String) -> Self {
        Self {
            id: json_string(&content, "id")
                .unwrap_or_else(|| "production-verification-blocker".to_string()),
            status: json_string(&content, "status").unwrap_or_else(|| "failed".to_string()),
            severity: json_string(&content, "severity").unwrap_or_else(|| "blocking".to_string()),
            message: json_string(&content, "message")
                .unwrap_or_else(|| "production signature verification blocker".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningBlocker {
    pub id: String,
    pub severity: String,
    pub status: String,
    pub evidence_path: String,
    pub safe_next_command: String,
    pub message: String,
}

impl SigningBlocker {
    fn new(
        id: impl Into<String>,
        status: impl Into<String>,
        evidence_path: impl Into<String>,
        safe_next_command: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity: "blocking".to_string(),
            status: status.into(),
            evidence_path: evidence_path.into(),
            safe_next_command: safe_next_command.into(),
            message: message.into(),
        }
    }

    fn render(&self) -> String {
        format!(
            "signing_blocker id=\"{}\" severity={} status={} evidence_path=\"{}\" safe_next_command=\"{}\" message=\"{}\"",
            safe_text(&self.id),
            safe_text(&self.severity),
            safe_text(&self.status),
            safe_text(&self.evidence_path),
            safe_text(&self.safe_next_command),
            safe_text(&self.message)
        )
    }
}

fn collect_blockers(
    provenance_present: bool,
    candidate_signatures: &[CandidateSignatureProjection],
    production_signatures: &[ProductionSignatureProjection],
    verification: &ProductionVerificationProjection,
) -> Vec<SigningBlocker> {
    let mut blockers = Vec::new();
    if !provenance_present {
        blockers.push(SigningBlocker::new(
            "release-provenance-missing",
            "missing",
            ".workflow/artifacts/release/provenance.json",
            "release.provenance.show",
            "release provenance is required before signing status can be trusted",
        ));
    }
    blockers.extend(
        candidate_signatures
            .iter()
            .filter(|signature| !signature.present)
            .map(|signature| {
                SigningBlocker::new(
                    format!("candidate-signature-missing:{}", signature.name),
                    "missing",
                    signature.path.clone(),
                    "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/build-release.ps1",
                    "required candidate detached signature is missing",
                )
            }),
    );
    blockers.extend(
        production_signatures
            .iter()
            .filter(|signature| !signature.present)
            .map(|signature| {
                SigningBlocker::new(
                    format!("production-signature-missing:{}", signature.name),
                    "missing",
                    signature.path.clone(),
                    PRODUCTION_VERIFICATION_SCRIPT,
                    "production detached signature is required before GA promotion",
                )
            }),
    );
    if !verification.present {
        blockers.push(SigningBlocker::new(
            "production-signature-verification-missing",
            "missing",
            verification.path.clone(),
            PRODUCTION_VERIFICATION_SCRIPT,
            "production signature verification result is missing",
        ));
    } else if verification.status != "passed" {
        blockers.push(SigningBlocker::new(
            "production-signature-verification-not-passed",
            verification.status.clone(),
            verification.path.clone(),
            PRODUCTION_VERIFICATION_SCRIPT,
            "production signature verification did not pass",
        ));
    }
    blockers.extend(verification.blockers.iter().map(|blocker| {
        SigningBlocker::new(
            format!("production-verification:{}", blocker.id),
            blocker.status.clone(),
            verification.path.clone(),
            PRODUCTION_VERIFICATION_SCRIPT,
            blocker.message.clone(),
        )
    }));
    blockers.sort_by(|left, right| left.id.cmp(&right.id));
    blockers.dedup_by(|left, right| left.id == right.id);
    blockers
}

fn production_status(
    verification: &ProductionVerificationProjection,
    production_missing: usize,
) -> &'static str {
    if !verification.present {
        "missing"
    } else if verification.status == "passed" && production_missing == 0 {
        "passed"
    } else {
        "blocked"
    }
}

fn production_verification_path(release_dir: &Path) -> PathBuf {
    release_dir
        .parent()
        .map(|parent| {
            parent
                .join("production-signature-verification")
                .join("result.json")
        })
        .unwrap_or_else(|| {
            resolve_repo_path(".workflow/artifacts/production-signature-verification/result.json")
        })
}

fn candidate_signature_file_for_name(name: &str) -> String {
    match name {
        "dependency_inventory" => "dependency-inventory.json.sig.json".to_string(),
        "update_metadata" => "update-metadata.json.sig.json".to_string(),
        other => format!("{}.json.sig.json", other.replace('_', "-")),
    }
}

fn artifact_file_for_name(name: &str) -> &'static str {
    match name {
        "dependency_inventory" => "dependency-inventory.json",
        "sbom" => "sbom.json",
        "update_metadata" => "update-metadata.json",
        "provenance" => "provenance.json",
        _ => "artifact.json",
    }
}

fn artifact_path_for_name(release_dir: &Path, artifacts_object: &str, name: &str) -> PathBuf {
    let object = json_object_section(artifacts_object, name).unwrap_or_default();
    let artifact_path =
        json_string(&object, "path").unwrap_or_else(|| artifact_file_for_name(name).to_string());
    resolve_artifact_path(release_dir, &artifact_path)
        .unwrap_or_else(|| release_dir.join(artifact_file_for_name(name)))
}

fn resolve_artifact_path(release_dir: &Path, value: &str) -> Option<PathBuf> {
    if value.trim().is_empty() || value == "-" {
        return None;
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else if path.components().count() == 1 {
        Some(release_dir.join(path))
    } else {
        Some(resolve_repo_path(value))
    }
}

fn json_objects_in_array(content: &str) -> Vec<String> {
    let mut objects = Vec::new();
    let mut offset = 0;
    while let Some(relative) = content[offset..].find('{') {
        let start = offset + relative;
        let Some(object) = balanced_from(content, start, '{', '}') else {
            break;
        };
        offset = start + object.len();
        objects.push(object);
    }
    objects
}

fn balanced_from(content: &str, start: usize, open: char, close: char) -> Option<String> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (relative, ch) in content[start..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            _ if in_string => {}
            value if value == open => depth += 1,
            value if value == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let end = start + relative + ch.len_utf8();
                    return Some(content[start..end].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn safe_join(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        safe_text(&values.join("|"))
    }
}

fn safe_text(value: &str) -> String {
    escape_json(&redact_summary(value))
}
