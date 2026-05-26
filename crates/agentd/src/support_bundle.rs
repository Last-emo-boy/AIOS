use std::path::{Path, PathBuf};
use std::{fs, io};

use runtime_contracts::{SupportBundleManifest, stable_contract_hash};

use crate::api::escape_json;
use crate::audit::AuditJournal;

pub const DEFAULT_ECOSYSTEM_REGISTRY_PATH: &str =
    "packaging/agentos/rootfs/etc/agentos/ecosystem/registry-snapshot.json";
pub const DEFAULT_ECOSYSTEM_LOCKFILE_PATH: &str = ".workflow/artifacts/aom/ecosystem-lock.json";
pub const DEFAULT_ECOSYSTEM_ACTIVE_SET_PATH: &str = ".workflow/artifacts/aom/active-set.json";
pub const DEFAULT_ECOSYSTEM_REPLAY_RESULT_PATH: &str =
    ".workflow/artifacts/ecosystem-replay/result.json";
pub const DEFAULT_SUPPORT_BUNDLE_NOW: &str = "2026-05-25T00:00:00Z";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleProjection {
    pub manifest: SupportBundleManifest,
    pub runtime: RuntimeSupportBundleProjection,
    pub recovery: RecoverySupportBundleProjection,
    pub ecosystem: EcosystemSupportBundleProjection,
    pub audit_excerpt_count: usize,
    pub deterministic: bool,
}

impl SupportBundleProjection {
    pub fn from_journal(
        journal: &AuditJournal,
        bundle_id: impl Into<String>,
        run_ids: Vec<impl Into<String>>,
    ) -> io::Result<Self> {
        let run_ids = run_ids.into_iter().map(Into::into).collect::<Vec<_>>();
        let lines = journal.event_lines()?;
        let first = if lines.is_empty() { 0 } else { 1 };
        let last = lines.len();
        let manifest = SupportBundleManifest::new(
            bundle_id,
            run_ids,
            format!("{first}..{last}"),
            audit_hash_chain(&lines),
            "secret-values-redacted",
            false,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.reason()))?;
        let runtime = RuntimeSupportBundleProjection::from_audit_lines(&lines)?;
        let recovery = RecoverySupportBundleProjection::from_audit_lines(&lines)?;
        let ecosystem = EcosystemSupportBundleProjection::from_defaults();
        Ok(Self {
            manifest,
            runtime,
            recovery,
            ecosystem,
            audit_excerpt_count: lines.len(),
            deterministic: true,
        })
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"manifest\":{},\"runtime\":{},\"recovery\":{},\"ecosystem\":{},\"audit_excerpt_count\":{},\"deterministic\":{}}}",
            self.manifest.to_json(),
            self.runtime.to_json(),
            self.recovery.to_json(),
            self.ecosystem.to_json(),
            self.audit_excerpt_count,
            self.deterministic
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSupportBundleProjection {
    pub schema_version: &'static str,
    pub loop_status: &'static str,
    pub latest_run_id: Option<String>,
    pub event_count: usize,
    pub effect_prepared_count: usize,
    pub commit_sealed_count: usize,
    pub unresolved_effect_count: usize,
    pub rollback_pending_count: usize,
    pub normal_shell_available: bool,
    pub model_output_direct_execution_allowed: bool,
    pub external_llm_required: bool,
    pub network_required: bool,
    pub runtime_authority: &'static str,
    pub redaction_status: &'static str,
}

impl RuntimeSupportBundleProjection {
    fn from_audit_lines(lines: &[String]) -> io::Result<Self> {
        let unresolved_effect_count = unresolved_effect_count(lines);
        let rollback_pending_count = count_event_type(lines, "RollbackPending");
        Ok(Self {
            schema_version: "agentos.support-bundle-runtime.v1",
            loop_status: if unresolved_effect_count > 0 || rollback_pending_count > 0 {
                "needs-reconciliation"
            } else if lines.is_empty() {
                "no-runtime-events"
            } else {
                "healthy"
            },
            latest_run_id: latest_json_string(lines, "run_id"),
            event_count: lines.len(),
            effect_prepared_count: count_event_type(lines, "EffectPrepared"),
            commit_sealed_count: count_event_type(lines, "CommitSealed"),
            unresolved_effect_count,
            rollback_pending_count,
            normal_shell_available: false,
            model_output_direct_execution_allowed: false,
            external_llm_required: false,
            network_required: false,
            runtime_authority: "AgentCore PlanSpec + SecurityExecutionEngine",
            redaction_status: "secret-values-redacted",
        })
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":\"{}\",\"loop_status\":\"{}\",\"latest_run_id\":{},\"event_count\":{},\"effect_prepared_count\":{},\"commit_sealed_count\":{},\"unresolved_effect_count\":{},\"rollback_pending_count\":{},\"normal_shell_available\":{},\"model_output_direct_execution_allowed\":{},\"external_llm_required\":{},\"network_required\":{},\"runtime_authority\":\"{}\",\"redaction_status\":\"{}\"}}",
            self.schema_version,
            self.loop_status,
            optional_json(self.latest_run_id.as_deref()),
            self.event_count,
            self.effect_prepared_count,
            self.commit_sealed_count,
            self.unresolved_effect_count,
            self.rollback_pending_count,
            self.normal_shell_available,
            self.model_output_direct_execution_allowed,
            self.external_llm_required,
            self.network_required,
            escape_json(self.runtime_authority),
            self.redaction_status
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySupportBundleProjection {
    pub schema_version: &'static str,
    pub recovery_status: &'static str,
    pub recovery_started_count: usize,
    pub recovery_completed_count: usize,
    pub unresolved_effect_count: usize,
    pub requires_human_review: bool,
    pub recovery_source_of_truth: &'static str,
    pub model_replay_authority: bool,
    pub redaction_status: &'static str,
}

impl RecoverySupportBundleProjection {
    fn from_audit_lines(lines: &[String]) -> io::Result<Self> {
        let recovery_started_count = count_event_type(lines, "RecoveryStarted");
        let recovery_completed_count = count_event_type(lines, "RecoveryCompleted");
        let unresolved_effect_count = unresolved_effect_count(lines);
        let requires_human_review = unresolved_effect_count > 0
            || recovery_started_count > recovery_completed_count
            || count_event_type(lines, "RollbackPending") > 0;
        let recovery_status = if requires_human_review {
            "needs-human-review"
        } else if recovery_completed_count > 0 {
            "reconciled"
        } else {
            "no-recovery-needed"
        };
        Ok(Self {
            schema_version: "agentos.support-bundle-recovery.v1",
            recovery_status,
            recovery_started_count,
            recovery_completed_count,
            unresolved_effect_count,
            requires_human_review,
            recovery_source_of_truth: "run-store+audit-journal",
            model_replay_authority: false,
            redaction_status: "secret-values-redacted",
        })
    }

    fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":\"{}\",\"recovery_status\":\"{}\",\"recovery_started_count\":{},\"recovery_completed_count\":{},\"unresolved_effect_count\":{},\"requires_human_review\":{},\"recovery_source_of_truth\":\"{}\",\"model_replay_authority\":{},\"redaction_status\":\"{}\"}}",
            self.schema_version,
            self.recovery_status,
            self.recovery_started_count,
            self.recovery_completed_count,
            self.unresolved_effect_count,
            self.requires_human_review,
            self.recovery_source_of_truth,
            self.model_replay_authority,
            self.redaction_status
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcosystemSupportBundleProjection {
    pub schema_version: &'static str,
    pub registry_snapshot_path: String,
    pub registry_snapshot_status: &'static str,
    pub registry_snapshot_hash: Option<String>,
    pub registry_snapshot_digest: Option<String>,
    pub registry_snapshot_expires_at: Option<String>,
    pub registry_snapshot_freshness: &'static str,
    pub registry_local_pinned: bool,
    pub registry_artifact_count: usize,
    pub trust_tiers: Vec<String>,
    pub lockfile_path: String,
    pub lockfile_status: &'static str,
    pub lockfile_hash: Option<String>,
    pub active_set_path: String,
    pub active_set_status: &'static str,
    pub active_set_hash: Option<String>,
    pub active_artifact_count: usize,
    pub active_artifacts: Vec<String>,
    pub replay_result_path: String,
    pub replay_status: &'static str,
    pub replay_result_hash: Option<String>,
    pub degraded_artifact_count: usize,
    pub revocation_status: &'static str,
    pub private_key_paths_included: bool,
    pub redaction_status: &'static str,
    pub agentd_resolver_logic: bool,
    pub activation_authority: &'static str,
    pub offline_baseline_status: &'static str,
    pub network_required: bool,
}

impl EcosystemSupportBundleProjection {
    pub fn from_defaults() -> Self {
        Self::from_paths(
            DEFAULT_ECOSYSTEM_REGISTRY_PATH,
            DEFAULT_ECOSYSTEM_LOCKFILE_PATH,
            DEFAULT_ECOSYSTEM_ACTIVE_SET_PATH,
            DEFAULT_ECOSYSTEM_REPLAY_RESULT_PATH,
        )
    }

    pub fn from_paths(
        registry_snapshot_path: &str,
        lockfile_path: &str,
        active_set_path: &str,
        replay_result_path: &str,
    ) -> Self {
        let registry_path = resolve_support_path(registry_snapshot_path);
        let lock_path = resolve_support_path(lockfile_path);
        let active_path = resolve_support_path(active_set_path);
        let replay_path = resolve_support_path(replay_result_path);

        let registry_content = read_optional(&registry_path);
        let active_content = read_optional(&active_path);
        let replay_content = read_optional(&replay_path);
        let trust_tiers = registry_content
            .as_deref()
            .map(|content| unique_sorted(json_string_values(content, "trust_tier")))
            .unwrap_or_default();
        let registry_snapshot_expires_at = registry_content
            .as_deref()
            .and_then(|content| json_string(content, "expires_at"));
        let registry_local_pinned = registry_content
            .as_deref()
            .and_then(|content| json_bool(content, "local_pinned"))
            .unwrap_or(false);
        let registry_snapshot_freshness = snapshot_freshness(
            registry_snapshot_expires_at.as_deref(),
            DEFAULT_SUPPORT_BUNDLE_NOW,
        );
        let network_required = registry_content
            .as_deref()
            .map(snapshot_network_required)
            .unwrap_or(false);
        let active_artifacts = active_content
            .as_deref()
            .map(|content| unique_sorted(json_string_values(content, "coordinate")))
            .unwrap_or_default();
        let degraded_artifact_count = replay_content
            .as_deref()
            .map(degraded_artifact_count)
            .unwrap_or(0);
        Self {
            schema_version: "agentos.support-bundle-ecosystem.v1",
            registry_snapshot_path: registry_snapshot_path.to_string(),
            registry_snapshot_status: file_status(&registry_path),
            registry_snapshot_hash: file_stable_hash(&registry_path),
            registry_snapshot_digest: registry_content
                .as_deref()
                .and_then(|content| json_string(content, "snapshot_digest")),
            registry_snapshot_expires_at,
            registry_snapshot_freshness,
            registry_local_pinned,
            registry_artifact_count: registry_content
                .as_deref()
                .map(|content| json_key_count(content, "coordinate"))
                .unwrap_or(0),
            trust_tiers,
            lockfile_path: lockfile_path.to_string(),
            lockfile_status: file_status(&lock_path),
            lockfile_hash: file_stable_hash(&lock_path),
            active_set_path: active_set_path.to_string(),
            active_set_status: file_status(&active_path),
            active_set_hash: file_stable_hash(&active_path),
            active_artifact_count: active_artifacts.len(),
            active_artifacts,
            replay_result_path: replay_result_path.to_string(),
            replay_status: replay_status(replay_content.as_deref()),
            replay_result_hash: file_stable_hash(&replay_path),
            degraded_artifact_count,
            revocation_status: if degraded_artifact_count > 0 {
                "degraded-active-artifact-visible"
            } else {
                "no-degraded-active-artifact"
            },
            private_key_paths_included: false,
            redaction_status: "secret-values-redacted",
            agentd_resolver_logic: false,
            activation_authority: "AgentCore PlanSpec + SecurityExecutionEngine",
            offline_baseline_status: if registry_local_pinned
                && registry_snapshot_freshness == "fresh"
                && !network_required
            {
                "pinned-local-ready"
            } else if registry_snapshot_freshness == "expired" {
                "degraded-expired-snapshot"
            } else {
                "degraded-missing-pinned-snapshot"
            },
            network_required,
        }
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":\"{}\",\"registry_snapshot_path\":\"{}\",\"registry_snapshot_status\":\"{}\",\"registry_snapshot_hash\":{},\"registry_snapshot_digest\":{},\"registry_snapshot_expires_at\":{},\"registry_snapshot_freshness\":\"{}\",\"registry_local_pinned\":{},\"registry_artifact_count\":{},\"trust_tiers\":{},\"lockfile_path\":\"{}\",\"lockfile_status\":\"{}\",\"lockfile_hash\":{},\"active_set_path\":\"{}\",\"active_set_status\":\"{}\",\"active_set_hash\":{},\"active_artifact_count\":{},\"active_artifacts\":{},\"replay_result_path\":\"{}\",\"replay_status\":\"{}\",\"replay_result_hash\":{},\"degraded_artifact_count\":{},\"revocation_status\":\"{}\",\"private_key_paths_included\":{},\"redaction_status\":\"{}\",\"agentd_resolver_logic\":{},\"activation_authority\":\"{}\",\"offline_baseline_status\":\"{}\",\"network_required\":{}}}",
            self.schema_version,
            escape_json(&self.registry_snapshot_path),
            self.registry_snapshot_status,
            optional_json(self.registry_snapshot_hash.as_deref()),
            optional_json(self.registry_snapshot_digest.as_deref()),
            optional_json(self.registry_snapshot_expires_at.as_deref()),
            self.registry_snapshot_freshness,
            self.registry_local_pinned,
            self.registry_artifact_count,
            string_array_json(&self.trust_tiers),
            escape_json(&self.lockfile_path),
            self.lockfile_status,
            optional_json(self.lockfile_hash.as_deref()),
            escape_json(&self.active_set_path),
            self.active_set_status,
            optional_json(self.active_set_hash.as_deref()),
            self.active_artifact_count,
            string_array_json(&self.active_artifacts),
            escape_json(&self.replay_result_path),
            self.replay_status,
            optional_json(self.replay_result_hash.as_deref()),
            self.degraded_artifact_count,
            self.revocation_status,
            self.private_key_paths_included,
            self.redaction_status,
            self.agentd_resolver_logic,
            escape_json(self.activation_authority),
            self.offline_baseline_status,
            self.network_required
        )
    }
}

fn audit_hash_chain(lines: &[String]) -> String {
    let mut state: u64 = 0xcbf29ce484222325;
    for line in lines {
        for byte in line.as_bytes() {
            state ^= *byte as u64;
            state = state.wrapping_mul(0x100000001b3);
        }
    }
    format!("fnv64:{state:016x}")
}

fn resolve_support_path(path: &str) -> PathBuf {
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

fn read_optional(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn file_status(path: &Path) -> &'static str {
    if path.is_file() { "present" } else { "missing" }
}

fn file_stable_hash(path: &Path) -> Option<String> {
    read_optional(path).map(|content| stable_contract_hash(&content))
}

fn json_key_count(content: &str, key: &str) -> usize {
    let needle = format!("\"{key}\"");
    content.match_indices(&needle).count()
}

fn json_string(content: &str, key: &str) -> Option<String> {
    json_string_values(content, key).into_iter().next()
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
        if let Some(end) = rest.find('"') {
            values.push(rest[..end].to_string());
            offset = value_start + end + 2;
        } else {
            break;
        }
    }
    values
}

fn count_event_type(lines: &[String], event_type: &str) -> usize {
    let needle = format!("\"event_type\":\"{event_type}\"");
    lines.iter().filter(|line| line.contains(&needle)).count()
}

fn latest_json_string(lines: &[String], key: &str) -> Option<String> {
    lines.iter().rev().find_map(|line| json_string(line, key))
}

fn unresolved_effect_count(lines: &[String]) -> usize {
    let prepared = lines
        .iter()
        .filter(|line| line.contains("\"event_type\":\"EffectPrepared\""))
        .filter_map(|line| json_string(line, "step_id"))
        .collect::<Vec<_>>();
    let sealed = lines
        .iter()
        .filter(|line| line.contains("\"event_type\":\"CommitSealed\""))
        .filter_map(|line| json_string(line, "step_id"))
        .collect::<Vec<_>>();
    let rolled_back = lines
        .iter()
        .filter(|line| line.contains("\"event_type\":\"RollbackObserved\""))
        .filter_map(|line| json_string(line, "step_id"))
        .collect::<Vec<_>>();
    prepared
        .iter()
        .filter(|step_id| !sealed.contains(step_id) && !rolled_back.contains(step_id))
        .count()
}

fn snapshot_freshness(expires_at: Option<&str>, now: &str) -> &'static str {
    match expires_at {
        Some(expires_at) if expires_at <= now => "expired",
        Some(_) => "fresh",
        None => "unknown",
    }
}

fn snapshot_network_required(content: &str) -> bool {
    !json_bool(content, "local_pinned").unwrap_or(false)
        || json_string_values(content, "source_uri")
            .iter()
            .any(|value| value.starts_with("http://") || value.starts_with("https://"))
}

fn unique_sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn degraded_artifact_count(content: &str) -> usize {
    let explicit_degraded = content.matches("\"degraded\": true").count()
        + content.matches("\"degraded\":true").count();
    if explicit_degraded > 0 {
        explicit_degraded
    } else if content.contains("\"revoked_active_artifact_degraded\": true")
        || content.contains("\"revoked_active_artifact_degraded\":true")
    {
        1
    } else {
        0
    }
}

fn replay_status(content: Option<&str>) -> &'static str {
    let Some(content) = content else {
        return "missing";
    };
    if content.contains("\"status\": \"passed\"") || content.contains("\"status\":\"passed\"") {
        "passed"
    } else if content.contains("\"status\": \"failed\"")
        || content.contains("\"status\":\"failed\"")
    {
        "failed"
    } else {
        "present"
    }
}

fn optional_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn string_array_json(values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{}\"", escape_json(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditEventType};

    #[test]
    fn support_bundle_manifest_links_runs_and_redacts() {
        let path = std::env::temp_dir().join(format!(
            "agentd-support-bundle-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let journal = AuditJournal::new(path);
        journal
            .append(&AuditEvent::new(
                AuditEventType::PolicyEvaluated,
                "run-support",
                "step-read",
                "operator",
                "decision=allow token=abc123 secret://handle",
            ))
            .expect("append");

        let projection = SupportBundleProjection::from_journal(
            &journal,
            "bundle-run-support",
            vec!["run-support"],
        )
        .expect("projection");

        assert_eq!(projection.audit_excerpt_count, 1);
        assert!(projection.deterministic);
        let json = projection.to_json();
        assert!(json.contains("agentos.support-bundle-manifest.v1"));
        assert!(json.contains("\"redaction_status\":\"secret-values-redacted\""));
        assert!(json.contains("\"includes_raw_secret\":false"));
        assert!(json.contains("\"runtime\":{"));
        assert!(json.contains("\"recovery\":{"));
        assert!(json.contains("\"ecosystem\":{"));
        assert!(json.contains("\"loop_status\":\"healthy\""));
        assert!(json.contains("\"normal_shell_available\":false"));
        assert!(json.contains("\"model_output_direct_execution_allowed\":false"));
        assert!(json.contains("\"model_replay_authority\":false"));
        assert!(json.contains("\"private_key_paths_included\":false"));
        assert!(json.contains("\"agentd_resolver_logic\":false"));
        assert!(json.contains("run-support"));
    }

    #[test]
    fn support_bundle_ecosystem_state_is_deterministic_and_redacted() {
        let root =
            std::env::temp_dir().join(format!("agentd-support-ecosystem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let registry_path = root.join("registry.json");
        let lockfile_path = root.join("lock.json");
        let active_set_path = root.join("active-set.json");
        let replay_path = root.join("replay.json");
        std::fs::write(
            &registry_path,
            r#"{"schema":"agentos.local-registry-snapshot.v1","snapshot_digest":"sha256:local","expires_at":"2026-06-01T00:00:00Z","local_pinned":true,"artifacts":[{"coordinate":"agentos:policy-pack/org/core@1.0.0","trust_tier":"core","revoked":false,"source_uri":"file:///core.json"},{"coordinate":"agentos:workflow-pack/community/demo@1.0.0","trust_tier":"community","revoked":true,"source_uri":"file:///demo.json"}]}"#,
        )
        .expect("registry");
        std::fs::write(&lockfile_path, r#"{"lock_hash":"sha256:lock"}"#).expect("lock");
        std::fs::write(
            &active_set_path,
            r#"{"schema":"agentos.active-artifact-set.v1","artifacts":[{"coordinate":"agentos:policy-pack/org/core@1.0.0"},{"coordinate":"agentos:workflow-pack/community/demo@1.0.0"}]}"#,
        )
        .expect("active");
        std::fs::write(
            &replay_path,
            r#"{"schema":"agentos.ecosystem-replay.v1","rollback_revocation":{"revoked_active_artifact_degraded":true},"status":"passed"}"#,
        )
        .expect("replay");

        let projection = EcosystemSupportBundleProjection::from_paths(
            &registry_path.to_string_lossy(),
            &lockfile_path.to_string_lossy(),
            &active_set_path.to_string_lossy(),
            &replay_path.to_string_lossy(),
        );

        assert_eq!(projection.registry_snapshot_status, "present");
        assert_eq!(projection.registry_snapshot_freshness, "fresh");
        assert!(projection.registry_local_pinned);
        assert_eq!(projection.registry_artifact_count, 2);
        assert_eq!(projection.trust_tiers, vec!["community", "core"]);
        assert_eq!(projection.active_artifact_count, 2);
        assert_eq!(projection.replay_status, "passed");
        assert_eq!(projection.degraded_artifact_count, 1);
        assert_eq!(
            projection.revocation_status,
            "degraded-active-artifact-visible"
        );
        assert!(!projection.private_key_paths_included);
        assert!(!projection.agentd_resolver_logic);
        assert_eq!(projection.offline_baseline_status, "pinned-local-ready");
        assert!(!projection.network_required);

        let json = projection.to_json();
        assert!(json.contains("\"registry_snapshot_hash\":\"sha256:agentos-stable-v1-"));
        assert!(json.contains("\"active_set_hash\":\"sha256:agentos-stable-v1-"));
        assert!(json.contains("\"offline_baseline_status\":\"pinned-local-ready\""));
        assert!(json.contains("\"network_required\":false"));
        assert!(json.contains("\"revocation_status\":\"degraded-active-artifact-visible\""));
        assert!(json.contains("\"trust_tiers\":[\"community\",\"core\"]"));
        assert!(!json.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!json.contains("/.ssh/"));
    }
}
