use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::escape_json;
use crate::audit::{AuditEvent, AuditEventType, AuditJournal};
use crate::policy::{stable_parameter_hash, CapabilityLease};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteDiffError {
    UnsupportedTool(String),
    BaseHashMismatch { expected: String, actual: String },
    Io(String),
}

impl WriteDiffError {
    pub fn reason(&self) -> String {
        match self {
            WriteDiffError::UnsupportedTool(tool) => {
                format!("rollback flow only supports fs.write.diff, got {tool}")
            }
            WriteDiffError::BaseHashMismatch { expected, actual } => {
                format!("base hash mismatch expected={expected} actual={actual}")
            }
            WriteDiffError::Io(error) => error.clone(),
        }
    }
}

impl From<io::Error> for WriteDiffError {
    fn from(value: io::Error) -> Self {
        WriteDiffError::Io(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub run_id: String,
    pub step_id: String,
    pub actor: String,
    pub target_path: PathBuf,
    pub proposed_content: String,
    pub base_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackHandle {
    pub rollback_id: String,
    pub target_path: PathBuf,
    pub base_hash: String,
    pub proposed_hash: String,
    pub parameter_hash: String,
    pub policy_version: String,
    pub previous_content_path: PathBuf,
    pub proposed_content_path: PathBuf,
    pub committed: bool,
}

impl RollbackHandle {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"rollback_id\":\"{}\",\"target_path\":\"{}\",\"base_hash\":\"{}\",\"proposed_hash\":\"{}\",\"parameter_hash\":\"{}\",\"policy_version\":\"{}\",\"previous_content_path\":\"{}\",\"proposed_content_path\":\"{}\",\"committed\":{}}}",
            escape_json(&self.rollback_id),
            escape_json(&self.target_path.display().to_string()),
            escape_json(&self.base_hash),
            escape_json(&self.proposed_hash),
            escape_json(&self.parameter_hash),
            escape_json(&self.policy_version),
            escape_json(&self.previous_content_path.display().to_string()),
            escape_json(&self.proposed_content_path.display().to_string()),
            self.committed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffPreview {
    pub target_path: PathBuf,
    pub base_hash: String,
    pub proposed_hash: String,
    pub rollback_id: String,
    pub unified_diff: String,
}

impl DiffPreview {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"target_path\":\"{}\",\"base_hash\":\"{}\",\"proposed_hash\":\"{}\",\"rollback_id\":\"{}\",\"unified_diff\":\"{}\"}}",
            escape_json(&self.target_path.display().to_string()),
            escape_json(&self.base_hash),
            escape_json(&self.proposed_hash),
            escape_json(&self.rollback_id),
            escape_json(&self.unified_diff)
        )
    }

    pub fn render(&self) -> String {
        format!(
            "Diff Preview\nTarget: {}\nBase: {}\nProposed: {}\nRollback: {}\n{}",
            self.target_path.display(),
            self.base_hash,
            self.proposed_hash,
            self.rollback_id,
            self.unified_diff
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWrite {
    pub lease: CapabilityLease,
    pub request: WriteRequest,
    pub handle: RollbackHandle,
    pub preview: DiffPreview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReport {
    pub committed: bool,
    pub target_path: PathBuf,
    pub rollback_id: String,
    pub base_hash: String,
    pub final_hash: String,
}

impl CommitReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"committed\":{},\"target_path\":\"{}\",\"rollback_id\":\"{}\",\"base_hash\":\"{}\",\"final_hash\":\"{}\"}}",
            self.committed,
            escape_json(&self.target_path.display().to_string()),
            escape_json(&self.rollback_id),
            escape_json(&self.base_hash),
            escape_json(&self.final_hash)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackReport {
    pub restored: bool,
    pub target_path: PathBuf,
    pub rollback_id: String,
    pub restored_hash: String,
}

impl RollbackReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"restored\":{},\"target_path\":\"{}\",\"rollback_id\":\"{}\",\"restored_hash\":\"{}\"}}",
            self.restored,
            escape_json(&self.target_path.display().to_string()),
            escape_json(&self.rollback_id),
            escape_json(&self.restored_hash)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteDiffExecutor {
    shadow_root: PathBuf,
}

impl WriteDiffExecutor {
    pub fn new(shadow_root: impl Into<PathBuf>) -> Self {
        Self {
            shadow_root: shadow_root.into(),
        }
    }

    pub fn prepare(
        &self,
        lease: &CapabilityLease,
        request: WriteRequest,
    ) -> Result<PreparedWrite, WriteDiffError> {
        if lease.tool != "fs.write.diff" {
            return Err(WriteDiffError::UnsupportedTool(lease.tool.clone()));
        }

        let previous = read_to_string_if_exists(&request.target_path)?;
        let actual_base = content_hash(&previous);
        if actual_base != request.base_hash {
            return Err(WriteDiffError::BaseHashMismatch {
                expected: request.base_hash,
                actual: actual_base,
            });
        }

        fs::create_dir_all(&self.shadow_root)?;
        let proposed_hash = content_hash(&request.proposed_content);
        let rollback_id = format!("rb-{}-{}", lease.parameter_hash, proposed_hash);
        let shadow_dir = self.shadow_root.join(&rollback_id);
        fs::create_dir_all(&shadow_dir)?;

        let previous_content_path = shadow_dir.join("previous.txt");
        let proposed_content_path = shadow_dir.join("proposed.txt");
        fs::write(&previous_content_path, previous.as_bytes())?;
        fs::write(&proposed_content_path, request.proposed_content.as_bytes())?;

        let handle = RollbackHandle {
            rollback_id: rollback_id.clone(),
            target_path: request.target_path.clone(),
            base_hash: request.base_hash.clone(),
            proposed_hash: proposed_hash.clone(),
            parameter_hash: lease.parameter_hash.clone(),
            policy_version: lease.policy_version.clone(),
            previous_content_path,
            proposed_content_path,
            committed: false,
        };
        let preview = DiffPreview {
            target_path: request.target_path.clone(),
            base_hash: request.base_hash.clone(),
            proposed_hash,
            rollback_id,
            unified_diff: unified_diff(&previous, &request.proposed_content),
        };

        Ok(PreparedWrite {
            lease: lease.clone(),
            request,
            handle,
            preview,
        })
    }

    pub fn commit(
        &self,
        journal: &AuditJournal,
        prepared: &mut PreparedWrite,
    ) -> Result<CommitReport, WriteDiffError> {
        let current = read_to_string_if_exists(&prepared.request.target_path)?;
        let current_hash = content_hash(&current);
        if current_hash != prepared.handle.base_hash {
            return Err(WriteDiffError::BaseHashMismatch {
                expected: prepared.handle.base_hash.clone(),
                actual: current_hash,
            });
        }

        let mut prepared_event = AuditEvent::new(
            AuditEventType::EffectPrepared,
            prepared.request.run_id.as_str(),
            prepared.request.step_id.as_str(),
            prepared.request.actor.as_str(),
            format!(
                "prepared fs.write.diff target={} rollback_id={} base_hash={} proposed_hash={}",
                prepared.request.target_path.display(),
                prepared.handle.rollback_id,
                prepared.handle.base_hash,
                prepared.handle.proposed_hash
            ),
        );
        prepared_event.policy_version = prepared.lease.policy_version.clone();
        prepared_event.tool_version = "fs.write.diff-v1".to_string();
        prepared_event.parameter_hash = prepared.lease.parameter_hash.clone();
        journal.append(&prepared_event)?;

        fs::write(
            &prepared.request.target_path,
            prepared.request.proposed_content.as_bytes(),
        )?;
        let final_content = read_to_string_if_exists(&prepared.request.target_path)?;
        let final_hash = content_hash(&final_content);
        if final_hash != prepared.handle.proposed_hash {
            let mut rollback_pending = AuditEvent::new(
                AuditEventType::RollbackPending,
                prepared.request.run_id.as_str(),
                prepared.request.step_id.as_str(),
                prepared.request.actor.as_str(),
                format!(
                    "rollback pending target={} rollback_id={} final_hash={}",
                    prepared.request.target_path.display(),
                    prepared.handle.rollback_id,
                    final_hash
                ),
            );
            annotate_write_event(&mut rollback_pending, prepared);
            journal.append(&rollback_pending)?;
            return Ok(CommitReport {
                committed: false,
                target_path: prepared.request.target_path.clone(),
                rollback_id: prepared.handle.rollback_id.clone(),
                base_hash: prepared.handle.base_hash.clone(),
                final_hash,
            });
        }

        let mut observed_event = AuditEvent::new(
            AuditEventType::EffectObserved,
            prepared.request.run_id.as_str(),
            prepared.request.step_id.as_str(),
            prepared.request.actor.as_str(),
            format!(
                "observed fs.write.diff target={} rollback_id={} final_hash={}",
                prepared.request.target_path.display(),
                prepared.handle.rollback_id,
                final_hash
            ),
        );
        annotate_write_event(&mut observed_event, prepared);
        journal.append(&observed_event)?;

        let mut sealed_event = AuditEvent::new(
            AuditEventType::CommitSealed,
            prepared.request.run_id.as_str(),
            prepared.request.step_id.as_str(),
            prepared.request.actor.as_str(),
            format!(
                "commit sealed fs.write.diff target={} rollback_id={} final_hash={}",
                prepared.request.target_path.display(),
                prepared.handle.rollback_id,
                final_hash
            ),
        );
        annotate_write_event(&mut sealed_event, prepared);
        journal.append(&sealed_event)?;
        prepared.handle.committed = true;

        Ok(CommitReport {
            committed: true,
            target_path: prepared.request.target_path.clone(),
            rollback_id: prepared.handle.rollback_id.clone(),
            base_hash: prepared.handle.base_hash.clone(),
            final_hash,
        })
    }

    pub fn rollback(
        &self,
        journal: &AuditJournal,
        handle: &RollbackHandle,
        run_id: &str,
        step_id: &str,
        actor: &str,
    ) -> Result<RollbackReport, WriteDiffError> {
        let mut pending_event = AuditEvent::new(
            AuditEventType::RollbackPending,
            run_id,
            step_id,
            actor,
            format!(
                "rollback pending target={} rollback_id={}",
                handle.target_path.display(),
                handle.rollback_id
            ),
        );
        annotate_handle_event(&mut pending_event, handle);
        journal.append(&pending_event)?;

        let previous = read_to_string_if_exists(&handle.previous_content_path)?;
        fs::write(&handle.target_path, previous.as_bytes())?;
        let restored = read_to_string_if_exists(&handle.target_path)?;
        let restored_hash = content_hash(&restored);

        let mut observed_event = AuditEvent::new(
            AuditEventType::RollbackObserved,
            run_id,
            step_id,
            actor,
            format!(
                "rollback observed target={} rollback_id={} restored_hash={}",
                handle.target_path.display(),
                handle.rollback_id,
                restored_hash
            ),
        );
        annotate_handle_event(&mut observed_event, handle);
        journal.append(&observed_event)?;

        Ok(RollbackReport {
            restored: restored_hash == handle.base_hash,
            target_path: handle.target_path.clone(),
            rollback_id: handle.rollback_id.clone(),
            restored_hash,
        })
    }
}

pub fn content_hash(content: &str) -> String {
    stable_parameter_hash(&[("content".to_string(), content.to_string())])
}

fn read_to_string_if_exists(path: &Path) -> Result<String, WriteDiffError> {
    if !path.exists() {
        return Ok(String::new());
    }
    Ok(fs::read_to_string(path)?)
}

fn annotate_write_event(event: &mut AuditEvent, prepared: &PreparedWrite) {
    event.policy_version = prepared.lease.policy_version.clone();
    event.tool_version = "fs.write.diff-v1".to_string();
    event.parameter_hash = prepared.lease.parameter_hash.clone();
}

fn annotate_handle_event(event: &mut AuditEvent, handle: &RollbackHandle) {
    event.policy_version = handle.policy_version.clone();
    event.tool_version = "fs.write.diff-v1".to_string();
    event.parameter_hash = handle.parameter_hash.clone();
}

fn unified_diff(before: &str, after: &str) -> String {
    let before_lines = before.lines().collect::<Vec<_>>();
    let after_lines = after.lines().collect::<Vec<_>>();
    let mut lines = vec!["--- before".to_string(), "+++ after".to_string()];
    let max = before_lines.len().max(after_lines.len());
    for index in 0..max {
        match (before_lines.get(index), after_lines.get(index)) {
            (Some(left), Some(right)) if left == right => lines.push(format!(" {left}")),
            (Some(left), Some(right)) => {
                lines.push(format!("-{left}"));
                lines.push(format!("+{right}"));
            }
            (Some(left), None) => lines.push(format!("-{left}")),
            (None, Some(right)) => lines.push(format!("+{right}")),
            (None, None) => {}
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_contracts::RiskClass;

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "agentd-rollback-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn test_journal(root: &Path) -> AuditJournal {
        AuditJournal::new(root.join("audit.jsonl"))
    }

    fn lease() -> CapabilityLease {
        CapabilityLease {
            lease_id: "lease-fs.write.diff-hash".to_string(),
            actor: "operator".to_string(),
            tool: "fs.write.diff".to_string(),
            resource: "/tmp/target.conf".to_string(),
            parameter_hash: "param-hash".to_string(),
            expires_at: 60,
            policy_version: "policy-v1".to_string(),
            risk: RiskClass::WriteWithDiff,
        }
    }

    fn request(target: PathBuf, base_hash: String, proposed: &str) -> WriteRequest {
        WriteRequest {
            run_id: "run-write".to_string(),
            step_id: "step-write".to_string(),
            actor: "operator".to_string(),
            target_path: target,
            proposed_content: proposed.to_string(),
            base_hash,
        }
    }

    #[test]
    fn prepare_generates_diff_and_does_not_mutate_target() {
        let root = temp_dir("prepare");
        let target = root.join("target.conf");
        fs::write(&target, "port=80\n").expect("write target");
        let base_hash = content_hash("port=80\n");
        let executor = WriteDiffExecutor::new(root.join("shadow"));
        let prepared = executor
            .prepare(&lease(), request(target.clone(), base_hash.clone(), "port=8080\n"))
            .expect("prepare");
        assert_eq!(fs::read_to_string(&target).expect("read target"), "port=80\n");
        assert_eq!(prepared.handle.base_hash, base_hash);
        assert_eq!(prepared.handle.proposed_hash, content_hash("port=8080\n"));
        assert!(prepared.preview.unified_diff.contains("-port=80"));
        assert!(prepared.preview.unified_diff.contains("+port=8080"));
        assert!(prepared.handle.previous_content_path.exists());
        assert!(prepared.handle.proposed_content_path.exists());
    }

    #[test]
    fn stale_base_hash_blocks_prepare() {
        let root = temp_dir("stale");
        let target = root.join("target.conf");
        fs::write(&target, "port=80\n").expect("write target");
        let executor = WriteDiffExecutor::new(root.join("shadow"));
        let error = executor
            .prepare(&lease(), request(target, "stale".to_string(), "port=8080\n"))
            .expect_err("stale base rejected");
        assert!(error.reason().contains("base hash mismatch"));
    }

    #[test]
    fn stale_base_hash_blocks_commit() {
        let root = temp_dir("commit-stale");
        let target = root.join("target.conf");
        fs::write(&target, "port=80\n").expect("write target");
        let executor = WriteDiffExecutor::new(root.join("shadow"));
        let journal = test_journal(&root);
        let mut prepared = executor
            .prepare(
                &lease(),
                request(target.clone(), content_hash("port=80\n"), "port=8080\n"),
            )
            .expect("prepare");
        fs::write(&target, "external-change\n").expect("external mutation");
        let error = executor
            .commit(&journal, &mut prepared)
            .expect_err("stale commit rejected");
        assert!(error.reason().contains("base hash mismatch"));
        assert_eq!(
            fs::read_to_string(&target).expect("read target"),
            "external-change\n"
        );
    }

    #[test]
    fn commit_writes_audit_events_and_seals_after_verification() {
        let root = temp_dir("commit");
        let target = root.join("target.conf");
        fs::write(&target, "port=80\n").expect("write target");
        let executor = WriteDiffExecutor::new(root.join("shadow"));
        let journal = test_journal(&root);
        let mut prepared = executor
            .prepare(
                &lease(),
                request(target.clone(), content_hash("port=80\n"), "port=8080\n"),
            )
            .expect("prepare");
        let report = executor.commit(&journal, &mut prepared).expect("commit");
        assert!(report.committed);
        assert_eq!(fs::read_to_string(&target).expect("read target"), "port=8080\n");
        let lines = journal.event_lines().expect("read journal");
        assert!(lines.iter().any(|line| line.contains("EffectPrepared")));
        assert!(lines.iter().any(|line| line.contains("EffectObserved")));
        assert!(lines.iter().any(|line| line.contains("CommitSealed")));
        assert!(lines.iter().any(|line| line.contains(&prepared.handle.rollback_id)));
        assert!(lines.iter().all(|line| line.contains("\"parameter_hash\":\"param-hash\"")));
        assert_eq!(prepared.handle.committed, true);
    }

    #[test]
    fn rollback_restores_previous_content_after_failed_verification_path() {
        let root = temp_dir("rollback");
        let target = root.join("target.conf");
        fs::write(&target, "port=80\n").expect("write target");
        let executor = WriteDiffExecutor::new(root.join("shadow"));
        let journal = test_journal(&root);
        let mut prepared = executor
            .prepare(
                &lease(),
                request(target.clone(), content_hash("port=80\n"), "port=8080\n"),
            )
            .expect("prepare");
        let _ = executor.commit(&journal, &mut prepared).expect("commit");
        fs::write(&target, "broken-after-verification\n").expect("simulate failed verification");
        let rollback = executor
            .rollback(
                &journal,
                &prepared.handle,
                "run-write",
                "step-write",
                "operator",
            )
            .expect("rollback");
        assert!(rollback.restored);
        assert_eq!(fs::read_to_string(&target).expect("read target"), "port=80\n");
        let lines = journal.event_lines().expect("read journal");
        assert!(lines.iter().any(|line| line.contains("RollbackPending")));
        assert!(lines.iter().any(|line| line.contains("RollbackObserved")));
        assert!(lines.iter().all(|line| line.contains("\"parameter_hash\":\"param-hash\"")));
    }
}
