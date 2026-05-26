use std::fs;
use std::path::{Path, PathBuf};

use crate::api::escape_json;
use crate::audit::redact_summary;
use crate::runtime_contracts::stable_contract_hash;

pub const RELEASE_PROVENANCE_PANEL_SCHEMA_VERSION: &str = "agentos.tui-release-provenance-panel.v1";
pub const DEFAULT_RELEASE_ARTIFACT_DIR: &str = ".workflow/artifacts/release";

const REQUIRED_RELEASE_FILES: &[&str] = &[
    "provenance.json",
    "dependency-inventory.json",
    "sbom.json",
    "update-metadata.json",
    "dependency-inventory.json.sig.json",
    "sbom.json.sig.json",
    "update-metadata.json.sig.json",
    "provenance.json.sig.json",
];

const PRIMARY_ARTIFACTS: &[&str] = &[
    "agentd_binary",
    "initramfs",
    "alpha_rootfs_manifest",
    "rootfs_runtime_manifest",
    "dependency_inventory",
    "sbom",
    "update_metadata",
];

const GATE_ARTIFACTS: &[&str] = &[
    "qemu_runtime_smoke",
    "alpha_service_recovery_smoke",
    "functional_capability_replay",
    "ecosystem_replay",
    "tui_replay",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseProvenancePanel {
    pub schema_version: &'static str,
    pub release_dir: String,
    pub provenance_path: String,
    pub provenance_present: bool,
    pub panel_status: String,
    pub schema: String,
    pub generated_at: String,
    pub source_commit: String,
    pub source_branch: String,
    pub dirty_worktree: bool,
    pub dirty_worktree_entries: usize,
    pub promotion_status: String,
    pub promotion_blockers: Vec<String>,
    pub promotion_warnings: Vec<String>,
    pub toolchain_cargo: String,
    pub toolchain_rustc: String,
    pub toolchain_powershell: String,
    pub gate_total: usize,
    pub gate_passed: usize,
    pub gate_failed: usize,
    pub gate_skipped: usize,
    pub gate_statuses: Vec<ReleaseGateProjection>,
    pub artifacts: Vec<ReleaseArtifactProjection>,
    pub gates: Vec<ReleaseArtifactProjection>,
    pub detached_signatures: Vec<ReleaseSignatureProjection>,
    pub dependency_inventory_packages: usize,
    pub sbom_packages: usize,
    pub update_metadata_schema: String,
    pub update_metadata_signature_policy: String,
    pub provenance_hash: String,
}

impl ReleaseProvenancePanel {
    pub fn collect() -> Self {
        Self::collect_from_dir(resolve_repo_path(DEFAULT_RELEASE_ARTIFACT_DIR))
    }

    pub fn collect_from_dir(release_dir: impl AsRef<Path>) -> Self {
        let release_dir = release_dir.as_ref().to_path_buf();
        let provenance_path = release_dir.join("provenance.json");
        let provenance_content = fs::read_to_string(&provenance_path).ok();
        let provenance_present = provenance_content.is_some();
        let source = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "source"))
            .unwrap_or_default();
        let toolchain = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "toolchain"))
            .unwrap_or_default();
        let promotion = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "promotion"))
            .unwrap_or_default();
        let artifacts_object = provenance_content
            .as_deref()
            .and_then(|content| json_object_section(content, "artifacts"))
            .unwrap_or_default();
        let gates_array = provenance_content
            .as_deref()
            .and_then(|content| json_array_section(content, "gates"))
            .unwrap_or_default();

        let dirty_status = json_string(&source, "git_status_porcelain").unwrap_or_default();
        let dirty_worktree_entries = dirty_status
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        let dirty_worktree = dirty_worktree_entries > 0;
        let mut promotion_blockers = json_string_array(&promotion, "blockers");
        let mut promotion_warnings = Vec::new();

        let required_file_statuses = REQUIRED_RELEASE_FILES
            .iter()
            .map(|file| {
                let present = release_dir.join(file).is_file();
                if !present {
                    promotion_blockers.push(format!("release-file-missing:{file}"));
                }
                ReleaseArtifactProjection {
                    name: (*file).to_string(),
                    path: release_dir.join(file).display().to_string(),
                    hash_kind: "content_hash".to_string(),
                    hash_value: file_content_hash(&release_dir.join(file)),
                    present,
                    required: true,
                    status: if present { "present" } else { "missing" }.to_string(),
                }
            })
            .collect::<Vec<_>>();

        if !provenance_present {
            promotion_blockers.push("provenance-missing".to_string());
        }
        if dirty_worktree {
            promotion_warnings.push("dirty-worktree".to_string());
        }

        let primary_artifacts = PRIMARY_ARTIFACTS
            .iter()
            .map(|name| artifact_projection(&release_dir, &artifacts_object, name, true))
            .collect::<Vec<_>>();
        let gate_artifacts = GATE_ARTIFACTS
            .iter()
            .map(|name| artifact_projection(&release_dir, &artifacts_object, name, true))
            .collect::<Vec<_>>();
        let gate_statuses = gate_statuses_from_array(&gates_array);
        let detached_signatures = collect_signature_projections(&release_dir, &provenance_content);
        let promotion_status = json_string(&promotion, "status").unwrap_or_else(|| {
            if provenance_present {
                "unknown".to_string()
            } else {
                "blocked".to_string()
            }
        });
        let panel_status = if !promotion_blockers.is_empty() || promotion_status == "blocked" {
            "blocked"
        } else if !promotion_warnings.is_empty() {
            "warning"
        } else {
            "ready"
        }
        .to_string();

        let dependency_inventory_packages =
            package_count(&fs::read_to_string(release_dir.join("dependency-inventory.json")).ok());
        let sbom_packages = package_count(&fs::read_to_string(release_dir.join("sbom.json")).ok());
        let update_metadata_content =
            fs::read_to_string(release_dir.join("update-metadata.json")).ok();
        let update_signature_policy = update_metadata_content
            .as_deref()
            .and_then(|content| json_object_section(content, "signature_policy"))
            .and_then(|section| json_string(&section, "status"))
            .unwrap_or_else(|| "missing".to_string());

        Self {
            schema_version: RELEASE_PROVENANCE_PANEL_SCHEMA_VERSION,
            release_dir: release_dir.display().to_string(),
            provenance_path: provenance_path.display().to_string(),
            provenance_present,
            panel_status,
            schema: provenance_content
                .as_deref()
                .and_then(|content| json_string(content, "schema"))
                .unwrap_or_else(|| "missing".to_string()),
            generated_at: provenance_content
                .as_deref()
                .and_then(|content| json_string(content, "generated_at"))
                .unwrap_or_else(|| "missing".to_string()),
            source_commit: json_string(&source, "git_commit").unwrap_or_else(|| "-".to_string()),
            source_branch: json_string(&source, "git_branch").unwrap_or_else(|| "-".to_string()),
            dirty_worktree,
            dirty_worktree_entries,
            promotion_status,
            promotion_blockers,
            promotion_warnings,
            toolchain_cargo: json_string(&toolchain, "cargo").unwrap_or_else(|| "-".to_string()),
            toolchain_rustc: json_string(&toolchain, "rustc").unwrap_or_else(|| "-".to_string()),
            toolchain_powershell: json_string(&toolchain, "powershell")
                .unwrap_or_else(|| "-".to_string()),
            gate_total: gate_statuses.len(),
            gate_passed: gate_statuses
                .iter()
                .filter(|gate| gate.status == "passed")
                .count(),
            gate_failed: gate_statuses
                .iter()
                .filter(|gate| gate.status == "failed")
                .count(),
            gate_skipped: gate_statuses
                .iter()
                .filter(|gate| gate.status == "skipped")
                .count(),
            gate_statuses,
            artifacts: primary_artifacts
                .into_iter()
                .chain(required_file_statuses)
                .collect(),
            gates: gate_artifacts,
            detached_signatures,
            dependency_inventory_packages,
            sbom_packages,
            update_metadata_schema: update_metadata_content
                .as_deref()
                .and_then(|content| json_string(content, "schema"))
                .unwrap_or_else(|| "missing".to_string()),
            update_metadata_signature_policy: update_signature_policy,
            provenance_hash: provenance_content
                .as_deref()
                .map(stable_contract_hash)
                .unwrap_or_else(|| "missing".to_string()),
        }
    }

    pub fn render(&self) -> String {
        let artifact_lines = self.artifacts.iter().map(|artifact| {
            format!(
                "artifact name={} status={} present={} required={} path=\"{}\" {}=\"{}\"",
                artifact.name,
                artifact.status,
                artifact.present,
                artifact.required,
                safe_text(&artifact.path),
                artifact.hash_kind,
                safe_text(&artifact.hash_value)
            )
        });
        let gate_lines = self.gates.iter().map(|artifact| {
            format!(
                "gate_artifact name={} status={} present={} required={} path=\"{}\" {}=\"{}\"",
                artifact.name,
                artifact.status,
                artifact.present,
                artifact.required,
                safe_text(&artifact.path),
                artifact.hash_kind,
                safe_text(&artifact.hash_value)
            )
        });
        let signature_lines = self.detached_signatures.iter().map(|signature| {
            format!(
                "detached_signature name={} status={} present={} production_key_required={} path=\"{}\" artifact_sha256=\"{}\" signature_hash=\"{}\" key_id=\"{}\" algorithm=\"{}\"",
                signature.name,
                signature.status,
                signature.present,
                signature.production_key_required,
                safe_text(&signature.path),
                safe_text(&signature.artifact_sha256),
                safe_text(&signature.signature_hash),
                safe_text(&signature.key_id),
                safe_text(&signature.algorithm)
            )
        });
        let mut lines = vec![
            "TUI Release Provenance".to_string(),
            format!(
                "release_provenance_panel schema={} read_only=true projection_controller_only=true release_authority=false promotion_authority=false direct_sign=false direct_promote=false build_script=\"scripts/build-release.ps1\"",
                self.schema_version
            ),
            format!(
                "provenance status={} present={} path=\"{}\" schema=\"{}\" generated_at=\"{}\" source_commit=\"{}\" source_branch=\"{}\" provenance_hash=\"{}\"",
                self.panel_status,
                self.provenance_present,
                safe_text(&self.provenance_path),
                safe_text(&self.schema),
                safe_text(&self.generated_at),
                safe_text(&self.source_commit),
                safe_text(&self.source_branch),
                safe_text(&self.provenance_hash)
            ),
            format!(
                "promotion status={} blockers=\"{}\" warnings=\"{}\" dirty_worktree={} dirty_worktree_entries={} missing_provenance={} promotion_warning={}",
                safe_text(&self.promotion_status),
                safe_join(&self.promotion_blockers),
                safe_join(&self.promotion_warnings),
                self.dirty_worktree,
                self.dirty_worktree_entries,
                !self.provenance_present,
                !self.promotion_warnings.is_empty()
            ),
            format!(
                "toolchain cargo=\"{}\" rustc=\"{}\" powershell=\"{}\"",
                safe_text(&self.toolchain_cargo),
                safe_text(&self.toolchain_rustc),
                safe_text(&self.toolchain_powershell)
            ),
            format!(
                "gate_summary total={} passed={} failed={} skipped={} failed_or_skipped_visible={}",
                self.gate_total,
                self.gate_passed,
                self.gate_failed,
                self.gate_skipped,
                self.gate_failed > 0 || self.gate_skipped > 0
            ),
            format!(
                "release_documents dependency_inventory_packages={} sbom_packages={} update_metadata_schema=\"{}\" update_metadata_signature_policy=\"{}\"",
                self.dependency_inventory_packages,
                self.sbom_packages,
                safe_text(&self.update_metadata_schema),
                safe_text(&self.update_metadata_signature_policy)
            ),
            "release_invariants artifact_generation_in_tui=false provenance_mutation_in_tui=false signing_status_mutation_in_tui=false production_ready_claim_by_tui=false hashes_and_paths_only=true redaction=secret-values-redacted".to_string(),
        ];
        lines.extend(artifact_lines);
        lines.extend(gate_lines);
        lines.extend(signature_lines);
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseArtifactProjection {
    pub name: String,
    pub path: String,
    pub hash_kind: String,
    pub hash_value: String,
    pub present: bool,
    pub required: bool,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseGateProjection {
    pub name: String,
    pub command: String,
    pub status: String,
    pub evidence_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSignatureProjection {
    pub name: String,
    pub path: String,
    pub artifact_sha256: String,
    pub signature_hash: String,
    pub key_id: String,
    pub algorithm: String,
    pub present: bool,
    pub production_key_required: bool,
    pub status: String,
}

fn gate_statuses_from_array(content: &str) -> Vec<ReleaseGateProjection> {
    json_objects_in_array(content)
        .into_iter()
        .map(|object| ReleaseGateProjection {
            name: json_string(&object, "name").unwrap_or_else(|| "-".to_string()),
            command: json_string(&object, "command").unwrap_or_else(|| "-".to_string()),
            status: json_string(&object, "status").unwrap_or_else(|| "unknown".to_string()),
            evidence_path: json_string(&object, "evidence_path")
                .or_else(|| json_string(&object, "evidence"))
                .unwrap_or_else(|| "-".to_string()),
        })
        .collect()
}

fn artifact_projection(
    release_dir: &Path,
    artifacts_object: &str,
    name: &str,
    required: bool,
) -> ReleaseArtifactProjection {
    let object = json_object_section(artifacts_object, name).unwrap_or_default();
    let path = json_string(&object, "path").unwrap_or_else(|| "-".to_string());
    let recorded_sha256 = json_string(&object, "sha256").unwrap_or_else(|| "-".to_string());
    let present = json_bool(&object, "present").unwrap_or_else(|| {
        if path == "-" {
            false
        } else {
            resolve_artifact_path(release_dir, &path)
                .map(|path| path.exists())
                .unwrap_or(false)
        }
    });
    let status = if object.is_empty() {
        "missing"
    } else if recorded_sha256 == "-" || recorded_sha256.trim().is_empty() {
        "missing-hash"
    } else if !present && required {
        "missing"
    } else {
        "recorded"
    }
    .to_string();
    ReleaseArtifactProjection {
        name: name.to_string(),
        path,
        hash_kind: "recorded_sha256".to_string(),
        hash_value: recorded_sha256,
        present,
        required,
        status,
    }
}

fn collect_signature_projections(
    release_dir: &Path,
    provenance_content: &Option<String>,
) -> Vec<ReleaseSignatureProjection> {
    let signing = provenance_content
        .as_deref()
        .and_then(|content| json_object_section(content, "signing"))
        .unwrap_or_default();
    let mut names = json_string_array(&signing, "required_detached_signatures");
    if names.is_empty() {
        names = vec![
            "dependency_inventory".to_string(),
            "sbom".to_string(),
            "update_metadata".to_string(),
            "provenance".to_string(),
        ];
    }
    names
        .into_iter()
        .map(|name| {
            let path = release_dir.join(signature_file_for_name(&name));
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
            let present = content.is_some();
            let artifact_sha256 =
                json_string(&artifact, "sha256").unwrap_or_else(|| "missing".to_string());
            let signature_hash =
                json_string(&signature, "value").unwrap_or_else(|| "missing".to_string());
            let algorithm =
                json_string(&signature, "algorithm").unwrap_or_else(|| "missing".to_string());
            let key_id = json_string(&key, "key_id").unwrap_or_else(|| "missing".to_string());
            let production_key_required = json_bool(&key, "production_key_required")
                .or_else(|| json_bool(&signing, "production_key_required"))
                .unwrap_or(false);
            ReleaseSignatureProjection {
                name,
                path: path.display().to_string(),
                artifact_sha256,
                signature_hash,
                key_id,
                algorithm,
                present,
                production_key_required,
                status: if present {
                    "present".to_string()
                } else {
                    "missing".to_string()
                },
            }
        })
        .collect()
}

fn signature_file_for_name(name: &str) -> String {
    let file = match name {
        "dependency_inventory" => "dependency-inventory.json.sig.json".to_string(),
        "update_metadata" => "update-metadata.json.sig.json".to_string(),
        other => {
            let leaf = other.replace('_', "-");
            format!("{leaf}.json.sig.json")
        }
    };
    file
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

fn file_content_hash(path: &Path) -> String {
    fs::read_to_string(path)
        .ok()
        .map(|content| stable_contract_hash(&content))
        .unwrap_or_else(|| "missing".to_string())
}

fn package_count(content: &Option<String>) -> usize {
    content
        .as_deref()
        .and_then(|content| json_array_section(content, "packages"))
        .map(|packages| json_object_count(&packages))
        .unwrap_or(0)
}

fn json_object_count(content: &str) -> usize {
    let mut count = 0;
    let mut in_string = false;
    let mut escaped = false;
    for ch in content.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' if !in_string => count += 1,
            _ => {}
        }
    }
    count
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

pub(crate) fn json_object_section(content: &str, key: &str) -> Option<String> {
    balanced_json_section(content, key, '{', '}')
}

pub(crate) fn json_array_section(content: &str, key: &str) -> Option<String> {
    balanced_json_section(content, key, '[', ']')
}

fn balanced_json_section(content: &str, key: &str, open: char, close: char) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut offset = 0;
    while let Some(relative_start) = content[offset..].find(&needle) {
        let key_start = offset + relative_start + needle.len();
        let colon_relative = content[key_start..].find(':')?;
        let mut value_start = key_start + colon_relative + 1;
        while content
            .as_bytes()
            .get(value_start)
            .is_some_and(u8::is_ascii_whitespace)
        {
            value_start += 1;
        }
        if content[value_start..].starts_with(open) {
            return balanced_from(content, value_start, open, close);
        }
        offset = value_start;
    }
    None
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

pub(crate) fn json_bool(content: &str, key: &str) -> Option<bool> {
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

pub(crate) fn json_string(content: &str, key: &str) -> Option<String> {
    json_string_values(content, key).into_iter().next()
}

pub(crate) fn json_string_array(content: &str, key: &str) -> Vec<String> {
    let Some(section) = json_array_section(content, key) else {
        return Vec::new();
    };
    string_values_from_array(&section)
}

fn string_values_from_array(content: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut chars = content.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        let mut escaped = false;
        for (_, ch) in chars.by_ref() {
            if escaped {
                value.push(unescape_json_char(ch));
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => {
                    values.push(value);
                    break;
                }
                _ => value.push(ch),
            }
        }
    }
    values
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
                value.push(unescape_json_char(ch));
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

fn unescape_json_char(ch: char) -> char {
    match ch {
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        other => other,
    }
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

pub(crate) fn resolve_repo_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    if path.is_absolute() || path.exists() {
        return path.to_path_buf();
    }
    let mut current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        let joined = current.join(path);
        if joined.exists() {
            return joined;
        }
        if !current.pop() {
            return path.to_path_buf();
        }
    }
}
